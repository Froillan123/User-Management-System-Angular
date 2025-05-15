import { Component, OnInit } from '@angular/core';
import { first } from 'rxjs/operators';

import { WorkflowService, EmployeeService } from '../../_services';
import { Workflow } from '../../_models/workflow';

@Component({ templateUrl: 'list.component.html' })
export class ListComponent implements OnInit {
    workflows: Workflow[] = [];
    pagedWorkflows: Workflow[] = [];
    loading = false;
    
    // Pagination
    currentPage = 0;
    pageSize = 5;
    totalPages = 0;
    
    constructor(
        private workflowService: WorkflowService,
        private employeeService: EmployeeService
    ) {}
    
    ngOnInit() {
        this.loadWorkflows();
    }
    
    loadWorkflows() {
        this.loading = true;
        this.workflowService.getAll()
            .pipe(first())
            .subscribe({
                next: workflows => {
                    // Filter out 'Request Status Update' workflow types
                    this.workflows = workflows.filter(w => w.type !== 'Request Status Update');
                    this.loadEmployeeDetails();
                },
                error: error => {
                    console.error('Error loading workflows:', error);
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
    
    loadEmployeeDetails() {
        // Get unique employee IDs
        const employeeIds = [...new Set(this.workflows
            .map(w => w.employeeId)
            .filter(id => id !== undefined) as number[])];
        
        // Load employee details for each workflow
        const promises = employeeIds.map(id => 
            this.employeeService.getById(id)
                .pipe(first())
                .toPromise()
                .catch(error => {
                    console.error(`Error loading employee ${id}:`, error);
                    return null;
                })
        );
        
        Promise.all(promises).then(employees => {
            // Map employees to workflows
            this.workflows.forEach(workflow => {
                const employee = employees.find(e => e && e.id === workflow.employeeId);
                if (employee) {
                    workflow.employee = employee;
                }
            });
            
            // Sort workflows by date (newest first)
            this.workflows.sort((a, b) => {
                const dateA = a.created ? new Date(a.created).getTime() : 0;
                const dateB = b.created ? new Date(b.created).getTime() : 0;
                return dateB - dateA;
            });
            
            // Setup pagination
            this.totalPages = Math.ceil(this.workflows.length / this.pageSize);
            this.setPage(0); // Initialize with first page
            
            this.loading = false;
        });
    }
} 