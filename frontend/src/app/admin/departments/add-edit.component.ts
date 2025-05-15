import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { first } from 'rxjs/operators';

import { DepartmentService, AlertService } from '@app/_services';

@Component({ templateUrl: 'add-edit.component.html' })
export class AddEditComponent implements OnInit {
    form!: FormGroup;
    id?: number;
    title!: string;
    loading = false;
    submitting = false;
    submitted = false;

    constructor(
        private formBuilder: FormBuilder,
        private route: ActivatedRoute,
        private router: Router,
        private departmentService: DepartmentService,
        private alertService: AlertService
    ) {}

    ngOnInit() {
        this.id = this.route.snapshot.params['id'];
        
        this.form = this.formBuilder.group({
            name: ['', Validators.required],
            description: ['']
        });
        
        this.title = 'Add Department';
        if (this.id) {
            // edit mode
            this.title = 'Edit Department';
            this.loading = true;
            this.departmentService.getById(this.id)
                .pipe(first())
                .subscribe(department => {
                    this.form.patchValue(department);
                    this.loading = false;
                });
        }
    }
    
    get f() { return this.form.controls; }
    
    onSubmit() {
        this.submitted = true;
        
        // reset alerts on submit
        this.alertService.clear();
        
        // stop here if form is invalid
        if (this.form.invalid) {
            return;
        }
        
        this.submitting = true;
        this.saveDepartment()
            .pipe(first())
            .subscribe({
                next: () => {
                    this.alertService.success('Department saved successfully', { keepAfterRouteChange: true });
                    this.router.navigateByUrl('/admin/departments');
                },
                error: error => {
                    this.alertService.error(error);
                    this.submitting = false;
                }
            });
    }
    
    private saveDepartment() {
        return this.id
            ? this.departmentService.update(this.id, this.form.value)
            : this.departmentService.create(this.form.value);
    }
} 