const express = require('express');
const router = express.Router();
const db = require('../_helpers/db');
const authorize = require('../_middleware/authorize');
const Role = require('../_helpers/role');

// Routes
router.get('/', authorize(), getAll);
router.get('/employee/:employeeId', authorize(), getByEmployeeId);
router.get('/:id', authorize(), getById);
router.post('/', authorize(), create);
router.put('/:id/status', authorize(), updateStatus);
router.put('/:id', authorize(), update);

// Get all workflows
async function getAll(req, res, next) {
    try {
        const workflows = await db.Workflow.findAll({
            include: [{ model: db.Employee }],
            order: [['created', 'DESC']]
        });
        res.json(workflows);
    } catch (err) { next(err); }
}

// Get workflows by employee ID
async function getByEmployeeId(req, res, next) {
    try {
        const workflows = await db.Workflow.findAll({
            where: { employeeId: req.params.employeeId },
            order: [['created', 'DESC']]
        });
        res.json(workflows);
    } catch (err) { next(err); }
}

// Get workflow by ID
async function getById(req, res, next) {
    try {
        const workflow = await db.Workflow.findByPk(req.params.id);
        if (!workflow) return res.status(404).json({ message: 'Workflow not found' });
        res.json(workflow);
    } catch (err) { next(err); }
}

// Create a new workflow
async function create(req, res, next) {
    try {
        const workflow = await db.Workflow.create(req.body);
        res.status(201).json(workflow);
    } catch (err) { next(err); }
}

// Update workflow status
async function updateStatus(req, res, next) {
    try {
        const workflow = await db.Workflow.findByPk(req.params.id);
        if (!workflow) return res.status(404).json({ message: 'Workflow not found' });
        
        await workflow.update({ status: req.body.status });
        res.json(workflow);
    } catch (err) { next(err); }
}

// Update entire workflow
async function update(req, res, next) {
    try {
        const workflow = await db.Workflow.findByPk(req.params.id);
        if (!workflow) return res.status(404).json({ message: 'Workflow not found' });
        
        // Update workflow preserving the ID and created date
        const { id, created, ...updateData } = req.body;
        await workflow.update(updateData);
        
        res.json(workflow);
    } catch (err) { next(err); }
}

module.exports = router; 