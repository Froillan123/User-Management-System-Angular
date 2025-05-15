import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { FormBuilder, FormGroup, FormArray, Validators } from '@angular/forms';
import { first } from 'rxjs/operators';

import { RequestService, AlertService, AccountService } from '@app/_services';

@Component({ templateUrl: 'add-edit.component.html' })
export class AddEditComponent implements OnInit {
    form!: FormGroup;
    id?: number;
    title!: string;
    loading = false;
    submitting = false;
    submitted = false;
    account: any;

    constructor(
        private formBuilder: FormBuilder,
        private route: ActivatedRoute,
        private router: Router,
        private requestService: RequestService,
        private accountService: AccountService,
        private alertService: AlertService
    ) {}

    ngOnInit() {
        this.id = this.route.snapshot.params['id'];
        
        // Get current user account
        this.accountService.account.subscribe(x => {
            this.account = x;
        });
        
        // Initialize form with items array
        this.form = this.formBuilder.group({
            type: ['', Validators.required],
            description: [''],
            status: ['Pending'],
            items: this.formBuilder.array([])
        });
        
        // Add at least one empty item
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
            description: [item?.description || ''],
            status: [item?.status || 'Pending']
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
                description: '',
                status: 'Pending'
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
                next: () => {
                    this.alertService.success('Request saved successfully', { keepAfterRouteChange: true });
                    this.router.navigateByUrl('/requests');
                },
                error: error => {
                    this.alertService.error(error);
                    this.submitting = false;
                }
            });
    }
    
    private saveRequest() {
        return this.id
            ? this.requestService.update(this.id, this.form.value)
            : this.requestService.create(this.form.value);
    }
} 