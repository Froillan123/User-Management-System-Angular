/**
 * Database rebuild script
 * Use this after running cleanup.js to recreate all tables
 * Usage: node rebuild-db.js
 */

// Import database initialization
const db = require('./_helpers/db');
console.log('Starting database rebuild process...');

// The database initialization will automatically create all tables
console.log('Database rebuild completed. Tables have been recreated.');
console.log('You can now restart the application with "npm start"'); 