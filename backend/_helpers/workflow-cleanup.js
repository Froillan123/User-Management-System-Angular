/**
 * This module cleans up duplicate workflow records
 * It can be run directly or imported and run from server startup
 */

const db = require('./db');

async function cleanupDuplicateTransfers() {
    try {
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
        
        console.log(`Transfer cleanup complete. Removed ${deletedCount} duplicate transfer workflows.`);
        return deletedCount;
    } catch (error) {
        console.error('Error during workflow cleanup:', error);
        throw error;
    }
}

async function cleanupDuplicateRequestApprovals() {
    try {
        console.log('Starting cleanup of duplicate Request Approval workflows...');
        
        // Get all Request Approval workflow records
        const approvalWorkflows = await db.Workflow.findAll({
            where: { type: 'Request Approval' },
            order: [['created', 'ASC']] // Process oldest first
        });
        
        console.log(`Found ${approvalWorkflows.length} request approval workflows...`);
        
        // Group workflows by request ID (from details)
        const workflowsByRequest = {};
        
        // Group the workflows by requestId from details
        approvalWorkflows.forEach(workflow => {
            if (workflow.details && workflow.details.requestId) {
                const requestId = workflow.details.requestId;
                if (!workflowsByRequest[requestId]) {
                    workflowsByRequest[requestId] = [];
                }
                workflowsByRequest[requestId].push(workflow);
            }
        });
        
        // Process each request's approval workflows
        let deletedCount = 0;
        
        for (const requestId in workflowsByRequest) {
            const workflows = workflowsByRequest[requestId];
            
            // If a request has multiple approval workflows, keep only the latest
            if (workflows.length > 1) {
                console.log(`Request ${requestId} has ${workflows.length} approval workflows`);
                
                // Sort by creation time (newest first)
                workflows.sort((a, b) => b.created.getTime() - a.created.getTime());
                
                // Keep the newest, delete the rest
                for (let i = 1; i < workflows.length; i++) {
                    console.log(`Deleting duplicate approval workflow ID: ${workflows[i].id}`);
                    await workflows[i].destroy();
                    deletedCount++;
                }
            }
        }
        
        console.log(`Request approval cleanup complete. Removed ${deletedCount} duplicate workflows.`);
        return deletedCount;
    } catch (error) {
        console.error('Error during request approval workflow cleanup:', error);
        throw error;
    }
}

async function cleanupAllDuplicateWorkflows() {
    try {
        const transferCount = await cleanupDuplicateTransfers();
        const approvalCount = await cleanupDuplicateRequestApprovals();
        const totalCount = transferCount + approvalCount;
        
        console.log(`All cleanup complete. Removed ${totalCount} duplicate workflows in total.`);
        return totalCount;
    } catch (error) {
        console.error('Error during complete workflow cleanup:', error);
        throw error;
    }
}

// Allow running directly from command line
if (require.main === module) {
    // Wait for DB initialization then run cleanup
    setTimeout(async () => {
        try {
            await cleanupAllDuplicateWorkflows();
            process.exit(0);
        } catch (error) {
            console.error('Error running cleanup script:', error);
            process.exit(1);
        }
    }, 1000);
}

module.exports = {
    cleanupDuplicateTransfers,
    cleanupDuplicateRequestApprovals,
    cleanupAllDuplicateWorkflows
}; 