/**
 * Database reset script - DROPS ALL TABLES
 * WARNING: This will delete all data in the database!
 * Usage: node drop-tables.js
 */

const config = require('./config.json');
const { Sequelize } = require('sequelize');

// Determine environment
const env = process.env.NODE_ENV === 'production' ? 'production' : 'development';
const envConfig = config[env];

console.log(`Using ${env} database configuration`);
console.log('WARNING: This script will DROP ALL TABLES in the database!');
console.log('Press Ctrl+C within 5 seconds to cancel...');

// Wait 5 seconds before proceeding
setTimeout(async () => {
    try {
        console.log('Proceeding with database reset...');
        
        // Connect to the database
        const sequelize = new Sequelize(envConfig.database.url, { 
            dialect: 'postgres',
            dialectOptions: {
                ssl: {
                    require: true,
                    rejectUnauthorized: false
                }
            },
            logging: console.log // Enable to see SQL queries
        });

        // Authenticate to make sure connection works
        await sequelize.authenticate();
        console.log('Database connection established successfully.');

        // Load all models
        console.log('Loading models...');
        const models = {
            Account: require('./accounts/account.model')(sequelize),
            RefreshToken: require('./accounts/refresh-token.model')(sequelize),
            Employee: require('./employees/employee.model')(sequelize),
            Department: require('./employees/department.model')(sequelize),
            Workflow: require('./employees/workflow.model')(sequelize),
            Request: require('./requests/request.model')(sequelize),
            RequestItem: require('./requests/requestItem.model')(sequelize)
        };

        // Drop all tables
        console.log('Dropping all tables...');
        await sequelize.sync({ force: true });
        
        console.log('All database tables have been dropped successfully!');
        console.log('The database is now empty and ready for fresh initialization.');
        
        // Exit the process
        process.exit(0);
    } catch (error) {
        console.error('Error during database reset:', error);
        process.exit(1);
    }
}, 5000); // 5 second delay 