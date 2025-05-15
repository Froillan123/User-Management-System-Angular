import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { first, switchMap } from 'rxjs/operators';
import { of } from 'rxjs';

import { WorkflowService, EmployeeService, AlertService, RequestService } from '../../_services';
import { Workflow } from '../../_models/workflow';

@Component({ templateUrl: 'workflows.component.html' })
export class WorkflowsComponent implements OnInit {
    id!: number;
    workflows: Workflow[] = [];
    pagedWorkflows: Workflow[] = [];
    employee: any;
    loading = false;
    updating = false;
    
    // Pagination
    currentPage = 0;
    pageSize = 5;
    totalPages = 0;
    
    constructor(
        private route: ActivatedRoute,
        private router: Router,
        private workflowService: WorkflowService,
        private employeeService: EmployeeService,
        private requestService: RequestService,
        private alertService: AlertService
    ) {}
    
    ngOnInit() {
        this.id = this.route.snapshot.params['id'];
        this.loadEmployee();
        this.loadWorkflows();
    }
    
    private loadEmployee() {
        this.employeeService.getById(this.id)
            .pipe(first())
            .subscribe({
                next: employee => {
                    this.employee = employee;
                },
                error: error => {
                    this.alertService.error(error);
                }
            });
    }
    
    private loadWorkflows() {
        this.loading = true;
        this.workflowService.getByEmployeeId(this.id)
            .pipe(first())
            .subscribe({
                next: workflows => {
                    // Filter out 'Request Created' and 'Request Status Update' workflow types per user request
                    this.workflows = workflows.filter(w => 
                        w.type !== 'Request Created' && 
                        w.type !== 'Request Status Update'
                    );
                    this.totalPages = Math.ceil(this.workflows.length / this.pageSize);
                    this.setPage(0);
                    this.loading = false;
                },
                error: error => {
                    this.alertService.error(error);
                    this.loading = false;
                }
            });
    }
    
    setPage(page: number) {
        if (page < 0 || page >= this.totalPages) {
            return;
        }
        
        this.currentPage = page;
        const start = this.currentPage * this.pageSize;
        const end = Math.min(start + this.pageSize, this.workflows.length);
        this.pagedWorkflows = this.workflows.slice(start, end);
    }
    
    updateWorkflowStatus(workflow: Workflow, event: any) {
        const newStatus = event.target.value;
        if (!newStatus || newStatus === 'default') return;
        
        // Reset the select element to prevent confusion
        setTimeout(() => {
            event.target.value = 'default';
        }, 0);
        
        // Ask for confirmation
        if (!confirm(`Are you sure you want to ${newStatus.toLowerCase()} this request? This action cannot be undone.`)) {
            return;
        }
        
        workflow.updating = true;
        
        // First update the workflow status
        this.workflowService.updateStatus(workflow.id as number, newStatus)
            .pipe(
                first(),
                switchMap(() => {
                    // If workflow type is 'Transfer' and it's approved
                    if (newStatus === 'Approved' && workflow.type === 'Transfer') {
                        const details = workflow.details || {};
                        const newDepartmentId = details.newDepartmentId;
                        
                        if (newDepartmentId) {
                            return this.employeeService.transfer(this.id, newDepartmentId).pipe(first());
                        }
                    }
                    
                    // If workflow type is 'Request Approval', update the corresponding request status
                    if (workflow.type === 'Request Approval' && workflow.details?.requestId) {
                        const requestId = workflow.details.requestId;
                        console.log('Updating request status:', requestId, newStatus);
                        return this.requestService.updateStatus(requestId, newStatus).pipe(first());
                    }
                    
                    // If none of the above conditions match, just return the workflow
                    return of(workflow);
                })
            )
            .subscribe({
                next: () => {
                    this.alertService.success(`Workflow ${newStatus.toLowerCase()}`);
                    workflow.status = newStatus;
                    workflow.updating = false;
                    
                    // Reload workflows to get updated data after a short delay
                    setTimeout(() => this.loadWorkflows(), 1000);
                },
                error: error => {
                    this.alertService.error(`Failed to update status: ${error}`);
                    workflow.updating = false;
                }
            });
    }

    formatDetails(details: any): string {
        if (!details) return 'No details available';
        
        // If it's already a string, return it
        if (typeof details === 'string') return details;
        
        // Create a formatted string from the object
        let formattedText = '';
        Object.keys(details).forEach(key => {
            // Skip certain keys that we don't want to display
            if (['id', '__typename'].includes(key)) return;
            
            // Format the key name nicely
            const formattedKey = key.replace(/([A-Z])/g, ' $1')
                .replace(/^./, str => str.toUpperCase())
                .replace(/Id$/, 'ID');
            
            // Format the value
            let value = details[key];
            if (value === null || value === undefined) value = 'Not specified';
            else if (typeof value === 'object') value = this.formatDetails(value);
            
            // Add the formatted key-value pair to the result
            formattedText += `${formattedKey}: ${value}, `;
        });
        
        // Remove the trailing comma and space
        return formattedText.replace(/,\s$/, '');
    }
} 