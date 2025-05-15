const express = require('express');
const router = express.Router();
const db = require('../_helpers/db');
const authorize = require('../_middleware/authorize');
const Role = require('../_helpers/role');

router.post('/', authorize(Role.Admin), create);
router.get('/', authorize(), getAll);
router.get('/users', authorize(Role.Admin), getUsers);
router.get('/:id', authorize(), getById);
router.put('/:id', authorize(Role.Admin), update);
router.delete('/:id', authorize(Role.Admin), _delete);
router.post('/:id/transfer', authorize(Role.Admin), transfer);

async function create(req, res, next) {
    try {
        // Auto-generate employeeId if not provided
        if (!req.body.employeeId) {
            // Find the latest employee to determine the next ID
            const employees = await db.Employee.findAll({
                order: [['id', 'DESC']],
                limit: 1
            });
            
            let nextNum = 1;
            if (employees && employees.length > 0) {
                // Try to extract the number from the last employeeId
                const lastId = employees[0].employeeId || '';
                const match = lastId.match(/EMP(\d+)/);
                if (match && match[1]) {
                    nextNum = parseInt(match[1]) + 1;
                }
            }
            
            // Format with leading zeros (EMP001, EMP002, etc.)
            req.body.employeeId = `EMP${String(nextNum).padStart(3, '0')}`;
        }

        // Check if an employee is already linked to this account
        if (req.body.accountId) {
            const existingEmployeeWithAccount = await db.Employee.findOne({ 
                where: { accountId: req.body.accountId } 
            });
            if (existingEmployeeWithAccount) {
                return res.status(400).json({ 
                    message: `This account is already linked to an employee record` 
                });
            }
        }
        
        // If employeeId is provided but no names, try to get them from the linked account
        if (req.body.accountId && (!req.body.firstName || !req.body.lastName || !req.body.email)) {
            const account = await db.Account.findByPk(req.body.accountId);
            if (account) {
                req.body.firstName = account.firstName;
                req.body.lastName = account.lastName;
                req.body.email = account.email;
            }
        }
        
        // If still missing required fields, set default values
        if (!req.body.firstName) req.body.firstName = 'Employee';
        if (!req.body.lastName) req.body.lastName = req.body.employeeId || 'New';
        if (!req.body.email) req.body.email = `${req.body.employeeId || 'employee'}@example.com`;
        
        const employee = await db.Employee.create(req.body);
        res.status(201).json(employee);
    } catch (err) { next(err); }
}

async function getAll(req, res, next) {
    try {
        const employees = await db.Employee.findAll();
        
        // Get departments for employees separately
        const employeesWithDetails = await Promise.all(employees.map(async (emp) => {
            const empJson = emp.toJSON();
            let department = null;
            
            if (emp.departmentId) {
                department = await db.Department.findByPk(emp.departmentId);
            }
            
            // Get account information if accountId is present
            let user = null;
            if (emp.accountId) {
                user = await db.Account.findByPk(emp.accountId, {
                    attributes: ['id', 'email', 'firstName', 'lastName', 'role']
                });
            }
            
            return {
                ...empJson,
                department: department ? department.toJSON() : null,
                user: user ? user.toJSON() : null
            };
        }));
        
        res.json(employeesWithDetails);
    } catch (err) { next(err); }
}

async function getUsers(req, res, next) {
    try {
        // Get all accounts that can be assigned to employees
        const users = await db.Account.findAll({
            attributes: ['id', 'email', 'firstName', 'lastName', 'role']
        });
        res.json(users);
    } catch (err) { next(err); }
}

async function getById(req, res, next) {
    try {
        const employee = await db.Employee.findByPk(req.params.id);
        if (!employee) throw new Error('Employee not found');
        
        // Get department 
        let department = null;
        if (employee.departmentId) {
            department = await db.Department.findByPk(employee.departmentId);
        }
        
        // Get account information if accountId is present
        let user = null;
        if (employee.accountId) {
            user = await db.Account.findByPk(employee.accountId, {
                attributes: ['id', 'email', 'firstName', 'lastName', 'role']
            });
        }
        
        res.json({
            ...employee.toJSON(),
            department: department ? department.toJSON() : null,
            user: user ? user.toJSON() : null
        });
    } catch (err) { next(err); }
}

async function update(req, res, next) {
    try {
        const employee = await db.Employee.findByPk(req.params.id);
        if (!employee) throw new Error('Employee not found');
        
        // If changing account, update name and email
        if (req.body.accountId && req.body.accountId !== employee.accountId) {
            const account = await db.Account.findByPk(req.body.accountId);
            if (account) {
                req.body.firstName = account.firstName;
                req.body.lastName = account.lastName;
                req.body.email = account.email;
            }
        }
        
        await employee.update(req.body);
        res.json(employee);
    } catch (err) { next(err); }
}

async function _delete(req, res, next) {
    try {
        const employee = await db.Employee.findByPk(req.params.id);
        if (!employee) throw new Error('Employee not found');
        
        // Check if employee has a linked account
        if (employee.accountId) {
            throw new Error('Cannot delete employee with a linked account. Please unlink the account first.');
        }
        
        // Check if employee has any requests
        const hasRequests = await db.Request.findOne({ where: { employeeId: employee.id } });
        if (hasRequests) {
            throw new Error('Cannot delete employee with existing requests. Please delete requests first.');
        }
        
        // Check if employee is a department manager
        const isDepartmentManager = await db.Department.findOne({ where: { managerId: employee.id } });
        if (isDepartmentManager) {
            throw new Error('Cannot delete employee who is a department manager. Please assign a new manager first.');
        }
        
        // Delete any workflows associated with this employee
        await db.Workflow.destroy({ where: { employeeId: employee.id } });
        
        // Now delete the employee
        await employee.destroy();
        res.json({ message: 'Employee deleted successfully' });
    } catch (err) { next(err); }
}

async function transfer(req, res, next) {
    try {
        const employee = await db.Employee.findByPk(req.params.id);
        if (!employee) throw new Error('Employee not found');
        
        // Store old department info
        const oldDepartmentId = employee.departmentId;
        let oldDepartment = null;
        if (oldDepartmentId) {
            oldDepartment = await db.Department.findByPk(oldDepartmentId);
        }
        
        // Get new department info
        let newDepartment = null;
        if (req.body.departmentId) {
            newDepartment = await db.Department.findByPk(req.body.departmentId);
        }
        
        // Check if department has actually changed
        if (oldDepartmentId === req.body.departmentId) {
            return res.json({
                message: 'Employee is already in this department',
                departmentId: req.body.departmentId,
                departmentName: newDepartment ? newDepartment.name : 'Unknown'
            });
        }
        
        // Update employee
        await employee.update({ departmentId: req.body.departmentId });
        
        // Let frontend handle the workflow creation
        res.json({ 
            message: 'Employee transferred successfully',
            from: oldDepartment ? oldDepartment.name : 'None',
            to: newDepartment ? newDepartment.name : 'Unknown',
            oldDepartmentId: oldDepartmentId,
            newDepartmentId: req.body.departmentId,
            oldDepartmentName: oldDepartment ? oldDepartment.name : 'None',
            newDepartmentName: newDepartment ? newDepartment.name : 'Unknown',
        });
    } catch (err) { next(err); }
}

module.exports = router; 