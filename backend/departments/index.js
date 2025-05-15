const express = require('express');
const router = express.Router();
const db = require('../_helpers/db');
const authorize = require('../_middleware/authorize');
const Role = require('../_helpers/role');

router.post('/', authorize(Role.Admin), create);
router.get('/', authorize(), getAll);
router.get('/:id', authorize(), getById);
router.put('/:id', authorize(Role.Admin), update);
router.delete('/:id', authorize(Role.Admin), _delete);

async function create(req, res, next) {
    try {
        const department = await db.Department.create(req.body);
        res.status(201).json(department);
    } catch (err) { next(err); }
}

async function getAll(req, res, next) {
    try {
        const departments = await db.Department.findAll();
        
        // Get employee counts separately to avoid Sequelize relationship issues
        const departmentsWithCount = await Promise.all(departments.map(async (dept) => {
            const count = await db.Employee.count({ where: { departmentId: dept.id } });
            const deptJson = dept.toJSON();
            return {
                ...deptJson,
                employeeCount: count
            };
        }));
        
        res.json(departmentsWithCount);
    } catch (err) { next(err); }
}

async function getById(req, res, next) {
    try {
        const department = await db.Department.findByPk(req.params.id);
        if (!department) throw new Error('Department not found');
        
        // Get employee count separately
        const employeeCount = await db.Employee.count({ 
            where: { departmentId: department.id } 
        });
        
        res.json({ 
            ...department.toJSON(), 
            employeeCount 
        });
    } catch (err) { next(err); }
}

async function update(req, res, next) {
    try {
        const department = await db.Department.findByPk(req.params.id);
        if (!department) throw new Error('Department not found');
        await department.update(req.body);
        res.json(department);
    } catch (err) { next(err); }
}

async function _delete(req, res, next) {
    try {
        const department = await db.Department.findByPk(req.params.id);
        if (!department) throw new Error('Department not found');
        await department.destroy();
        res.json({ message: 'Department deleted' });
    } catch (err) { next(err); }
}

module.exports = router; 