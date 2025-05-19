const config = require('../config.json');
const { Sequelize } = require('sequelize');
const EventEmitter = require('events');

// Create an event emitter for database initialization
const dbEvents = new EventEmitter();

// Determine environment
const env = process.env.NODE_ENV === 'production' ? 'production' : 'development';
const envConfig = config[env];

module.exports = db = {
    events: dbEvents
};

initialize();

async function initialize() {
    try {
        console.log(`Using ${env} database configuration`);
        
        // Connect Sequelize with MySQL using connection details
        const sequelize = new Sequelize(
            envConfig.database.database,
            envConfig.database.user,
            envConfig.database.password, 
            { 
                host: envConfig.database.host,
                dialect: 'mysql',
                logging: console.log // Enable to see SQL queries
            }
        );

        // Add sequelize instance to db object for transactions
        db.sequelize = sequelize;
        
        // Initialize models
        db.Account = require('../accounts/account.model')(sequelize);
        db.RefreshToken = require('../accounts/refresh-token.model')(sequelize);
        db.Employee = require('../employees/employee.model')(sequelize);
        db.Department = require('../employees/department.model')(sequelize);
        db.Workflow = require('../employees/workflow.model')(sequelize);
        db.Request = require('../requests/request.model')(sequelize);
        db.RequestItem = require('../requests/requestItem.model')(sequelize);

        // Setup relationships
        db.Account.hasMany(db.RefreshToken, { onDelete: 'CASCADE' });
        db.RefreshToken.belongsTo(db.Account);

        // Employee-Department relationship
        db.Department.hasMany(db.Employee, { foreignKey: 'departmentId' });
        db.Employee.belongsTo(db.Department, { foreignKey: 'departmentId' });

        // Employee-Workflow relationship
        db.Employee.hasMany(db.Workflow, { foreignKey: 'employeeId' });
        db.Workflow.belongsTo(db.Employee, { foreignKey: 'employeeId' });

        // Account-Employee relationship
        db.Account.hasOne(db.Employee, { foreignKey: 'accountId' });
        db.Employee.belongsTo(db.Account, { foreignKey: 'accountId' });
        
        // Request-Employee relationship
        db.Employee.hasMany(db.Request, { foreignKey: 'employeeId' });
        db.Request.belongsTo(db.Employee, { foreignKey: 'employeeId' });

        // Request-RequestItem relationship
        db.Request.hasMany(db.RequestItem, { foreignKey: 'requestId', onDelete: 'CASCADE' });
        db.RequestItem.belongsTo(db.Request, { foreignKey: 'requestId' });

        // Sync models
        await sequelize.authenticate();
        await sequelize.sync({ alter: true });
        console.log('Database synchronized');
        
        // Emit event when database is fully initialized
        dbEvents.emit('initialized');
        
    } catch (err) {
        console.error('Database initialization failed:', err);
        process.exit(1);
    }
}