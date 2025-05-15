const express = require('express');
const router = express.Router();
const db = require('../_helpers/db');
const authorize = require('../_middleware/authorize');
const Role = require('../_helpers/role');

router.post('/', authorize(), create);
router.get('/', authorize(Role.Admin), getAll);
router.get('/:id', authorize(), getById);
router.get('/employee/:employeeId', authorize(), getByEmployeeId);
router.put('/:id', authorize(Role.Admin), update);
router.put('/:id/status', authorize(), updateStatus);
router.delete('/:id', authorize(Role.Admin), _delete);

async function create(req, res, next) {
    try {
        // Ensure employeeId is properly set
        if (!req.body.employeeId && req.user) {
            // Get the employee ID from the account
            const account = await db.Account.findByPk(req.user.id);
            if (account) {
                // Find the employee linked to this account
                const employee = await db.Employee.findOne({
                    where: { accountId: account.id }
                });
                
                if (employee) {
                    req.body.employeeId = employee.id;
                } else {
                    throw new Error('No employee record found for this account');
                }
            }
        }
        
        // Create the request without items initially
        const request = await db.Request.create({
            employeeId: req.body.employeeId || req.user.employeeId,
            type: req.body.type,
            status: req.body.status || 'Pending'
        });
        
        let items = [];
        
        // Process and create request items if they exist
        if (req.body.items && Array.isArray(req.body.items) && req.body.items.length > 0) {
            // Map items and add the requestId
            const requestItems = req.body.items.map(item => ({
                requestId: request.id,
                name: item.name || 'Unnamed Item',
                quantity: item.quantity || 1,
                status: item.status || 'Pending'
            }));
            
            // Create all items in the database
            items = await db.RequestItem.bulkCreate(requestItems);
            
            // Format items for the response and workflow
            items = items.map(item => item.toJSON());
        }
        
        // Format items for the workflow
        const itemsList = items.map(item => `${item.name} (x${item.quantity})`);
        
        // Create workflow for request creation ONLY
        await db.Workflow.create({
            employeeId: request.employeeId,
            type: 'Request Created',
            status: 'Completed',
            details: {
                requestId: request.id,
                requestType: request.type,
                itemCount: items.length,
                items: itemsList,
                message: `New ${request.type} request created with ${items.length} item(s)`
            }
        });
        
        // REMOVED: No longer automatically creating "Request Approval" workflow here
        // The frontend should handle creating approval workflows if needed
        
        // Return the request with items
        const fullRequest = {
            ...request.toJSON(),
            items: items
        };
        
        res.status(201).json(fullRequest);
    } catch (err) { next(err); }
}

async function getAll(req, res, next) {
    try {
        const requests = await db.Request.findAll();
        
        // Get details for all requests
        const requestsWithDetails = await Promise.all(requests.map(async (req) => {
            const reqJson = req.toJSON();
            
            // Get items for this request
            const items = await db.RequestItem.findAll({
                where: { requestId: req.id }
            });
            
            // Get employee information
            const employee = await db.Employee.findByPk(req.employeeId);
            
            return {
                ...reqJson,
                items: items.map(item => item.toJSON()),
                employee: employee ? employee.toJSON() : null
            };
        }));
        
        res.json(requestsWithDetails);
    } catch (err) { next(err); }
}

async function getById(req, res, next) {
    try {
        const request = await db.Request.findByPk(req.params.id);
        if (!request) throw new Error('Request not found');
        
        // Check if user is admin or the request belongs to the user
        if (req.user.role !== Role.Admin && request.employeeId !== req.user.employeeId) {
            throw new Error('Unauthorized');
        }
        
        // Get items for this request
        const items = await db.RequestItem.findAll({
            where: { requestId: request.id }
        });
        
        // Get employee information
        const employee = await db.Employee.findByPk(request.employeeId);
        
        const fullRequest = {
            ...request.toJSON(),
            items: items.map(item => item.toJSON()),
            employee: employee ? employee.toJSON() : null
        };
        
        res.json(fullRequest);
    } catch (err) { next(err); }
}

async function getByEmployeeId(req, res, next) {
    try {
        const requests = await db.Request.findAll({
            where: { employeeId: req.params.employeeId }
        });
        
        // Get items for all requests
        const requestsWithItems = await Promise.all(requests.map(async (req) => {
            const reqJson = req.toJSON();
            
            // Get items for this request
            const items = await db.RequestItem.findAll({
                where: { requestId: req.id }
            });
            
            return {
                ...reqJson,
                items: items.map(item => item.toJSON())
            };
        }));
        
        res.json(requestsWithItems);
    } catch (err) { next(err); }
}

async function update(req, res, next) {
    try {
        const request = await db.Request.findByPk(req.params.id);
        if (!request) throw new Error('Request not found');
        
        // Store old status for comparison
        const oldStatus = request.status;
        
        // Update request (excluding items)
        await request.update({
            employeeId: req.body.employeeId,
            type: req.body.type,
            status: req.body.status
        });
        
        let items = [];
        
        // Update request items if provided
        if (req.body.items && Array.isArray(req.body.items)) {
            // Delete existing items
            await db.RequestItem.destroy({ where: { requestId: request.id }});
            
            // Create new items
            if (req.body.items.length > 0) {
                const requestItems = req.body.items.map(item => ({
                    requestId: request.id,
                    name: item.name || 'Unnamed Item',
                    quantity: item.quantity || 1,
                    status: item.status || 'Pending'
                }));
                
                items = await db.RequestItem.bulkCreate(requestItems);
                items = items.map(item => item.toJSON());
            }
        } else {
            // Fetch current items if not provided in the request
            const existingItems = await db.RequestItem.findAll({ 
                where: { requestId: request.id } 
            });
            items = existingItems.map(item => item.toJSON());
        }
        
        // Format items for workflow
        const itemsList = items.map(item => `${item.name} (x${item.quantity})`);
        
        // Create workflow entry if status changed
        if (req.body.status && oldStatus !== req.body.status) {
            await db.Workflow.create({
                employeeId: request.employeeId,
                type: 'Request Status Update',
                status: 'Completed',
                details: {
                    requestId: request.id,
                    requestType: request.type,
                    oldStatus: oldStatus,
                    newStatus: req.body.status,
                    updatedBy: req.user.role,
                    items: itemsList,
                    message: `Request #${request.id} status changed from ${oldStatus} to ${req.body.status}`
                }
            });
        }
        
        // Return the updated request with items
        const fullRequest = {
            ...request.toJSON(),
            items: items
        };
        
        res.json(fullRequest);
    } catch (err) { next(err); }
}

async function updateStatus(req, res, next) {
    try {
        const request = await db.Request.findByPk(req.params.id);
        if (!request) throw new Error('Request not found');
        
        // Store old status for comparison
        const oldStatus = request.status;
        
        // Update request status
        await request.update({
            status: req.body.status
        });
        
        // Create workflow entry if status changed
        if (req.body.status && oldStatus !== req.body.status) {
            await db.Workflow.create({
                employeeId: request.employeeId,
                type: 'Request Status Update',
                status: 'Completed',
                details: {
                    requestId: request.id,
                    requestType: request.type,
                    oldStatus: oldStatus,
                    newStatus: req.body.status,
                    updatedBy: req.user.role,
                    message: `Request #${request.id} status changed from ${oldStatus} to ${req.body.status}`
                }
            });
        }
        
        // Return the updated request
        const fullRequest = {
            ...request.toJSON()
        };
        
        res.json(fullRequest);
    } catch (err) { next(err); }
}

async function _delete(req, res, next) {
    try {
        const request = await db.Request.findByPk(req.params.id);
        if (!request) throw new Error('Request not found');
        
        await request.destroy();
        res.json({ message: 'Request deleted' });
    } catch (err) { next(err); }
}

module.exports = router; 