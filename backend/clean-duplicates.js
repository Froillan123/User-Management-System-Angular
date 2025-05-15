/**
 * This script removes duplicate Transfer workflow records
 * Run with: node clean-duplicates.js
 */

const db = require('./_helpers/db');

async function cleanupDuplicateTransfers() {
    try {
        // Wait for the database to initialize
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        console.log('Starting cleanup of duplicate Transfer workflows...');
        
        // Get all workflow records
        const allWorkflows = await db.Workflow.findAll({
            where: { type: 'Transfer' },
            order: [['created', 'ASC']] // Process oldest first
        });
        
        console.log(`Found ${allWorkflows.length} transfer workflows...`);
        
        // Group workflows by employeeId
        const workflowsByEmployee = {};
        
        allWorkflows.forEach(workflow => {
            const employeeId = workflow.employeeId;
            if (!workflowsByEmployee[employeeId]) {
                workflowsByEmployee[employeeId] = [];
            }
            workflowsByEmployee[employeeId].push(workflow);
        });
        
        // Process each employee's workflows
        let deletedCount = 0;
        
        for (const employeeId in workflowsByEmployee) {
            const workflows = workflowsByEmployee[employeeId];
            
            // If an employee has multiple transfer workflows on the same day, keep only the latest
            // Group by date (ignoring time)
            const workflowsByDate = {};
            
            workflows.forEach(workflow => {
                const created = workflow.created;
                const dateStr = created.toISOString().split('T')[0]; // Get YYYY-MM-DD
                
                if (!workflowsByDate[dateStr]) {
                    workflowsByDate[dateStr] = [];
                }
                workflowsByDate[dateStr].push(workflow);
            });
            
            // For each date with multiple transfers, keep only the latest
            for (const dateStr in workflowsByDate) {
                const dateWorkflows = workflowsByDate[dateStr];
                
                if (dateWorkflows.length > 1) {
                    console.log(`Employee ${employeeId} has ${dateWorkflows.length} transfers on ${dateStr}`);
                    
                    // Sort by creation time (newest first)
                    dateWorkflows.sort((a, b) => b.created.getTime() - a.created.getTime());
                    
                    // Keep the newest, delete the rest
                    for (let i = 1; i < dateWorkflows.length; i++) {
                        console.log(`Deleting duplicate transfer workflow ID: ${dateWorkflows[i].id}`);
                        await dateWorkflows[i].destroy();
                        deletedCount++;
                    }
                }
            }
        }
        
        console.log(`Cleanup complete. Removed ${deletedCount} duplicate transfer workflows.`);
        
        // Ensure the database connection is properly closed
        setTimeout(() => {
            console.log('Exiting script');
            process.exit(0);
        }, 1000);
        
    } catch (error) {
        console.error('Error during cleanup:', error);
        process.exit(1);
    }
}

cleanupDuplicateTransfers(); 