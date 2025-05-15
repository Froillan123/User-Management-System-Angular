import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { first, switchMap, catchError } from 'rxjs/operators';
import { of } from 'rxjs';

import { EmployeeService, DepartmentService, AlertService, WorkflowService } from '../../_services';
import { Department } from '../../_models/department';
import { AccountService } from '../../_services/account.service';

@Component({ templateUrl: 'add-edit.component.html' })
export class AddEditComponent implements OnInit {
    form!: FormGroup;
    id?: number;
    title!: string;
    loading = false;
    submitting = false;
    submitted = false;
    departments: Department[] = [];
    users: any[] = [];
    errorMessage: string = '';

    constructor(
        private formBuilder: FormBuilder,
        private route: ActivatedRoute,
        private router: Router,
        private employeeService: EmployeeService,
        private departmentService: DepartmentService,
        private accountService: AccountService,
        private alertService: AlertService,
        private workflowService: WorkflowService
    ) {}

    ngOnInit() {
        this.id = this.route.snapshot.params['id'];
        
        // Load departments for dropdown
        this.loadDepartments();
        
        // Load users for account dropdown
        this.loadUsers();
        
        this.form = this.formBuilder.group({
            employeeId: [''],
            accountId: [null],
            position: ['', Validators.required],
            departmentId: ['', Validators.required],
            hireDate: [this.formatDate(new Date()), Validators.required],
            status: ['Active']
        });
        
        this.title = 'Add Employee';
        if (this.id) {
            // edit mode
            this.title = 'Edit Employee';
            this.loading = true;
            this.employeeService.getById(this.id)
                .pipe(first())
                .subscribe({
                    next: (employee: any) => {
                        // Convert the date format for the form
                        const formData = {
                            ...employee,
                            hireDate: employee.hireDate ? this.formatDate(new Date(employee.hireDate)) : this.formatDate(new Date())
                        };

                        // Check if user exists and set the accountId
                        if (employee.user) {
                            formData.accountId = employee.user.id;
                        }

                        this.form.patchValue(formData);
                        this.loading = false;
                    },
                    error: error => {
                        this.errorMessage = error;
                        this.loading = false;
                    }
                });
        }
    }
    
    // Format date to YYYY-MM-DD for input[type=date]
    private formatDate(date: Date): string {
        const d = new Date(date);
        let month = '' + (d.getMonth() + 1);
        let day = '' + d.getDate();
        const year = d.getFullYear();

        if (month.length < 2) month = '0' + month;
        if (day.length < 2) day = '0' + day;

        return [year, month, day].join('-');
    }
    
    private loadDepartments() {
        this.departmentService.getAll()
            .pipe(first())
            .subscribe({
                next: departments => {
                    this.departments = departments;
                },
                error: error => {
                    this.errorMessage = error;
                }
            });
    }
    
    private loadUsers() {
        // Use the getUsers method from the EmployeeService
        this.employeeService.getUsers()
            .pipe(first())
            .subscribe({
                next: users => {
                    this.users = users;
                },
                error: error => {
                    this.errorMessage = error;
                }
            });
    }
    
    // When account is selected, update the form with the account details
    onAccountChange() {
        // No longer need to set employeeId since it's auto-generated
        const accountId = this.form.get('accountId')?.value;
        // Keep this method in case we need to add other logic when account changes
    }
    
    get f() { return this.form.controls; }
    
    onSubmit() {
        this.submitted = true;
        
        // reset alerts on submit
        this.alertService.clear();
        this.errorMessage = '';
        
        // stop here if form is invalid
        if (this.form.invalid) {
            return;
        }
        
        this.submitting = true;
        this.saveEmployee()
            .pipe(
                first(),
                switchMap(employee => {
                    // Only create workflow for new employees (not when editing)
                    if (!this.id && employee) {
                        // Get department name
                        const departmentId = this.form.get('departmentId')?.value;
                        const department = this.departments.find(d => d.id == departmentId);
                        const departmentName = department ? department.name : 'Unknown Department';
                        
                        // Create onboarding workflow
                        return this.workflowService.create({
                            employeeId: employee.id,
                            type: 'Onboarding',
                            details: {
                                message: `Added to ${departmentName}`,
                                departmentId: departmentId,
                                departmentName: departmentName
                            },
                            status: 'Completed'
                        }).pipe(
                            // Return employee to maintain the flow
                            switchMap(() => of(employee)),
                            catchError(error => {
                                console.error('Error creating onboarding workflow:', error);
                                // Continue the flow even if workflow creation fails
                                return of(employee);
                            })
                        );
                    }
                    return of(employee);
                })
            )
            .subscribe({
                next: () => {
                    this.alertService.success('Employee saved successfully', { keepAfterRouteChange: true });
                    this.router.navigateByUrl('/admin/employees');
                },
                error: error => {
                    // Display the error message from the server
                    this.errorMessage = error.message || 'Could not save employee. Please try again.';
                    this.alertService.error(this.errorMessage);
                    this.submitting = false;
                    
                    // If error is about account already linked
                    if (this.errorMessage.includes('account is already linked')) {
                        this.form.get('accountId')?.setErrors({ duplicate: true });
                    }
                }
            });
    }
    
    onCancel() {
        this.router.navigateByUrl('/admin/employees');
    }
    
    private saveEmployee() {
        return this.id
            ? this.employeeService.update(this.id, this.form.value)
            : this.employeeService.create(this.form.value);
    }
} 