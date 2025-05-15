import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { first } from 'rxjs/operators';

import { RequestService, EmployeeService, AlertService, WorkflowService } from '@app/_services';
import { Request } from '@app/_models/request';

@Component({ templateUrl: 'requests.component.html' })
export class RequestsComponent implements OnInit {
    id!: number;
    requests: Request[] = [];
    employee: any;
    loading = false;
    updating = false;
    
    constructor(
        private route: ActivatedRoute,
        private requestService: RequestService,
        private employeeService: EmployeeService,
        private workflowService: WorkflowService,
        private alertService: AlertService
    ) {}
    
    ngOnInit() {
        this.id = this.route.snapshot.params['id'];
        this.loadEmployee();
        this.loadRequests();
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
    
    private loadRequests() {
        this.loading = true;
        this.requestService.getByEmployeeId(this.id)
            .pipe(first())
            .subscribe({
                next: requests => {
                    this.requests = requests;
                    this.loading = false;
                },
                error: error => {
                    this.alertService.error(error);
                    this.loading = false;
                }
            });
    }
    
    updateRequestStatus(request: Request, event: any) {
        const newStatus = event.target.value;
        if (!newStatus || newStatus === 'default') return;
        
        this.updating = true;
        request.updating = true;
        
        // Update the request status
        this.requestService.update(request.id as number, { ...request, status: newStatus })
            .pipe(first())
            .subscribe({
                next: () => {
                    this.alertService.success(`Request status updated to ${newStatus}`);
                    request.status = newStatus;
                    request.updating = false;
                    this.updating = false;
                    
                    // Create a workflow entry for this action
                    this.createWorkflowRecord(request, newStatus);
                },
                error: error => {
                    this.alertService.error(`Failed to update status: ${error}`);
                    request.updating = false;
                    this.updating = false;
                }
            });
    }
    
    private createWorkflowRecord(request: Request, status: string) {
        // Create workflow record for status change
        const workflow = {
            employeeId: this.id,
            type: 'Request Status Update',
            status: 'Completed',
            details: {
                requestId: request.id,
                requestType: request.type,
                oldStatus: request.status,
                newStatus: status,
                message: `Request ${request.id} status changed to ${status}`
            }
        };
        
        this.workflowService.create(workflow)
            .pipe(first())
            .subscribe({
                error: error => {
                    console.error('Failed to create workflow record:', error);
                }
            });
    }
} 