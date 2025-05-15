import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { FormBuilder, FormGroup, FormArray, Validators } from '@angular/forms';
import { first } from 'rxjs/operators';

import { RequestService, EmployeeService, AlertService, WorkflowService } from '../../_services';
import { Employee } from '../../_models/employee';

@Component({ templateUrl: 'add-edit.component.html' })
export class AddEditComponent implements OnInit {
    form!: FormGroup;
    id?: number;
    title!: string;
    loading = false;
    submitting = false;
    submitted = false;
    employees: Employee[] = [];

    constructor(
        private formBuilder: FormBuilder,
        private route: ActivatedRoute,
        private router: Router,
        private requestService: RequestService,
        private employeeService: EmployeeService,
        private workflowService: WorkflowService,
        private alertService: AlertService
    ) {}

    ngOnInit() {
        this.id = this.route.snapshot.params['id'];
        
        // Load employees for dropdown
        this.employeeService.getAll()
            .pipe(first())
            .subscribe(employees => {
                this.employees = employees;
            });
        
        // Initialize form with items array
        this.form = this.formBuilder.group({
            employeeId: ['', Validators.required],
            type: ['', Validators.required],
            status: ['Pending'],
            items: this.formBuilder.array([])
        });
        
        // Add at least one empty item to prevent errors
        this.addItem();
        
        this.title = 'Add Request';
        if (this.id) {
            // edit mode
            this.title = 'Edit Request';
            this.loading = true;
            this.requestService.getById(this.id)
                .pipe(first())
                .subscribe(request => {
                    this.form.patchValue(request);
                    
                    // Load request items
                    if (request.items && request.items.length) {
                        this.clearItems();
                        request.items.forEach(item => {
                            this.itemsFormArray.push(this.createItemFormGroup(item));
                        });
                    }
                    
                    this.loading = false;
                });
        }
    }
    
    get f() { return this.form.controls; }
    get itemsFormArray() { return this.form.get('items') as FormArray; }
    
    createItemFormGroup(item?: any) {
        return this.formBuilder.group({
            id: [item?.id],
            name: [item?.name || '', Validators.required],
            quantity: [item?.quantity || 1, [Validators.required, Validators.min(1)]],
            status: [item?.status]
        });
    }
    
    addItem() {
        this.itemsFormArray.push(this.createItemFormGroup());
    }
    
    removeItem(index: number) {
        if (this.itemsFormArray.length > 1) {
            this.itemsFormArray.removeAt(index);
        } else {
            // Don't remove the last item, just reset it
            this.itemsFormArray.at(0).reset({
                id: null,
                name: '',
                quantity: 1,
                status: null // Set status to null when resetting the last item
            });
        }
    }
    
    clearItems() {
        while (this.itemsFormArray.length) {
            this.itemsFormArray.removeAt(0);
        }
    }
    
    onSubmit() {
        this.submitted = true;
        
        // reset alerts on submit
        this.alertService.clear();
        
        // stop here if form is invalid
        if (this.form.invalid) {
            return;
        }
        
        this.submitting = true;
        this.saveRequest()
            .pipe(first())
            .subscribe({
                next: (request) => {
                    // For new requests: Create a new workflow
                    if (!this.id) {
                        this.createRequestWorkflow(request);
                    } 
                    // For existing requests: Update the existing workflow items only
                    else {
                        this.updateRequestItems(request);
                    }
                    
                    this.alertService.success('Request saved successfully', { keepAfterRouteChange: true });
                    this.router.navigateByUrl('/admin/requests');
                },
                error: error => {
                    this.alertService.error(error);
                    this.submitting = false;
                }
            });
    }
    
    private saveRequest() {
        // Prepare form data with default status for items
        const formData = {...this.form.value};
        if (formData.items && Array.isArray(formData.items)) {
            formData.items = formData.items.map(item => ({
                ...item,
                status: 'Pending' // Always set status to Pending for database compatibility
            }));
        }
        
        return this.id
            ? this.requestService.update(this.id, formData)
            : this.requestService.create(formData);
    }
    
    private updateRequestItems(request: any) {
        // Extract items for the workflow
        const itemsList = request.items?.map((item: any) => `${item.name} (${item.quantity})`) || [];
        
        // Find existing workflows for this request by requestId
        this.workflowService.findByRequestId(request.employeeId, request.id)
            .pipe(first())
            .subscribe(workflows => {
                // Find approval workflow for this request
                const approvalWorkflow = workflows.find(w => w.type === 'Request Approval');
                
                if (approvalWorkflow) {
                    // Only update the items in the workflow, preserve status
                    const updatedWorkflow = {
                        ...approvalWorkflow,
                        details: {
                            ...approvalWorkflow.details,
                            items: itemsList,
                            message: `Review ${request.type} request #${request.id} with ${request.items?.length || 0} items`,
                            updatedAt: new Date()
                        }
                    };
                    
                    // Update the workflow
                    this.workflowService.update(approvalWorkflow.id as number, updatedWorkflow)
                        .pipe(first())
                        .subscribe();
                } else {
                    // If no existing workflow found, create a new one
                    this.createRequestWorkflow(request);
                }
            });
    }
    
    private createRequestWorkflow(request: any) {
        // Extract items for the workflow
        const itemsList = request.items?.map((item: any) => `${item.name} (${item.quantity})`) || [];
            
        // For certain types of requests, create an approval workflow
        if (['Equipment', 'Resources', 'Training', 'Software', 'Travel'].includes(request.type)) {
            const approvalWorkflow = {
                employeeId: request.employeeId,
                type: 'Request Approval',
                status: 'Pending',
                details: {
                    requestId: request.id,
                    requestType: request.type,
                    requesterId: request.employeeId,
                    items: itemsList,
                    message: `Review ${request.type} request #${request.id} with ${request.items?.length || 0} items`
                }
            };
            
            this.workflowService.create(approvalWorkflow)
                .pipe(first())
                .subscribe({
                    error: error => {
                        console.error('Failed to create approval workflow record:', error);
                    }
                });
        }
    }
} 