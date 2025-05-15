/**
 * Database cleanup script - DROPS ALL TABLES
 * WARNING: This will delete all data in the database!
 * Usage: node cleanup.js
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
        console.log('Proceeding with database cleanup...');
        
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

        // Get all table names from the public schema
        const [tables] = await sequelize.query(`
            SELECT tablename FROM pg_catalog.pg_tables 
            WHERE schemaname = 'public'
        `);

        console.log('Tables to drop:', tables.map(t => t.tablename));

        // Disable foreign key checks
        await sequelize.query('SET CONSTRAINTS ALL DEFERRED');

        // Drop each table explicitly
        for (const table of tables) {
            const tableName = table.tablename;
            console.log(`Dropping table: ${tableName}`);
            await sequelize.query(`DROP TABLE IF EXISTS "${tableName}" CASCADE`);
        }

        // Re-enable foreign key checks
        await sequelize.query('SET CONSTRAINTS ALL IMMEDIATE');

        console.log('All database tables have been dropped successfully!');
        console.log('The database is now empty and ready for fresh initialization.');
        
        // Exit the process
        process.exit(0);
    } catch (error) {
        console.error('Error during database cleanup:', error);
        process.exit(1);
    }
}, 5000); // 5 second delay 