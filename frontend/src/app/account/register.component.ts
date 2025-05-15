import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute } from '@angular/router';
import { UntypedFormBuilder, UntypedFormGroup, Validators } from '@angular/forms';
import { first } from 'rxjs/operators';

import { AccountService, AlertService } from '../../app/_services';
import { MustMatch } from '../../app/_helpers';

@Component({ 
    templateUrl: 'register.component.html',
    styles: [`
        .step-indicator {
            display: flex;
            margin-bottom: 2rem;
            justify-content: center;
        }
        
        .step {
            display: flex;
            flex-direction: column;
            align-items: center;
            position: relative;
            z-index: 1;
        }
        
        .step-number {
            width: 3rem;
            height: 3rem;
            border-radius: 50%;
            background-color: #e9ecef;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #6c757d;
            font-weight: bold;
            margin-bottom: 0.5rem;
            transition: all 0.3s ease;
        }
        
        .step.active .step-number {
            background-color: #6610f2;
            color: white;
        }
        
        .step.completed .step-number {
            background-color: #20c997;
            color: white;
        }
        
        .step-title {
            font-size: 0.9rem;
            color: #6c757d;
            text-align: center;
        }
        
        .step.active .step-title {
            color: #6610f2;
            font-weight: bold;
        }
        
        .step.completed .step-title {
            color: #20c997;
        }
        
        .step-connector {
            position: absolute;
            top: 1.5rem;
            height: 2px;
            background-color: #e9ecef;
            width: 100%;
            z-index: 0;
        }
        
        .step-content {
            background-color: white;
            border-radius: 10px;
            box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.05);
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        
        .step-actions {
            display: flex;
            justify-content: space-between;
            margin-top: 2rem;
        }
        
        .fade-in {
            animation: fadeIn 0.5s ease;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .terms-modal-backdrop {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1050;
        }
        
        .terms-modal {
            width: 90%;
            max-width: 700px;
            max-height: 80vh;
            background-color: white;
            border-radius: 10px;
            box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
            overflow: hidden;
            display: flex;
            flex-direction: column;
            animation: modalOpen 0.3s ease-out;
        }
        
        .terms-modal-header {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid #e9ecef;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        
        .terms-modal-title {
            margin: 0;
            font-size: 1.25rem;
            font-weight: 600;
        }
        
        .terms-modal-body {
            padding: 1.5rem;
            overflow-y: auto;
        }
        
        .terms-modal-footer {
            padding: 1rem 1.5rem;
            border-top: 1px solid #e9ecef;
            display: flex;
            justify-content: flex-end;
        }
        
        @keyframes modalOpen {
            from { opacity: 0; transform: scale(0.95); }
            to { opacity: 1; transform: scale(1); }
        }
    `]
})
export class RegisterComponent implements OnInit {
    form: UntypedFormGroup;
    loading = false;
    submitted = false;
    currentStep = 1;
    totalSteps = 2;
    showTermsModal = false;

    constructor(
        private formBuilder: UntypedFormBuilder,
        private route: ActivatedRoute,
        private router: Router,
        private accountService: AccountService,
        private alertService: AlertService
    ) { }

    ngOnInit() {
        this.form = this.formBuilder.group({
            // Step 1: Account Info
            title: ['', Validators.required],
            firstName: ['', Validators.required],
            lastName: ['', Validators.required],
            
            // Step 2: Authentication
            email: ['', [Validators.required, Validators.email]],
            password: ['', [Validators.required, Validators.minLength(6)]],
            confirmPassword: ['', Validators.required],
            acceptTerms: [false, Validators.requiredTrue]
        }, {
            validator: MustMatch('password', 'confirmPassword')
        });
    }

    // convenience getter for easy access to form fields
    get f() { return this.form.controls; }

    nextStep() {
        const step1Fields = ['title', 'firstName', 'lastName'];
        
        // Check if current step fields are valid
        if (this.currentStep === 1) {
            let valid = true;
            for (const field of step1Fields) {
                if (this.form.get(field)?.invalid) {
                    this.form.get(field)?.markAsTouched();
                    valid = false;
                }
            }
            
            if (!valid) {
                return;
            }
        }
        
        if (this.currentStep < this.totalSteps) {
            this.currentStep++;
        }
    }
    
    prevStep() {
        if (this.currentStep > 1) {
            this.currentStep--;
        }
    }
    
    openTermsModal() {
        this.showTermsModal = true;
    }
    
    closeTermsModal() {
        this.showTermsModal = false;
    }

    onSubmit() {
        this.submitted = true;

        // reset alerts on submit
        this.alertService.clear();

        // stop here if form is invalid
        if (this.form.invalid) {
            // If we're not on the last step, go to the last step
            if (this.currentStep !== this.totalSteps) {
                this.currentStep = this.totalSteps;
            }
            return;
        }

        this.loading = true;
        this.accountService.register(this.form.value)
            .pipe(first())
            .subscribe({
                next: (response: any) => {
                    this.alertService.success(response.message || 'Registration successful', { keepAfterRouteChange: true });
                    this.router.navigate(['../login'], { relativeTo: this.route });
                },
                error: error => {
                    // Extract meaningful error message
                    let errorMessage = typeof error === 'string' ? error : 'Registration failed';
                    
                    // Check if it's an email-related error and highlight the email field
                    if (errorMessage.toLowerCase().includes('email') && 
                        errorMessage.toLowerCase().includes('already registered')) {
                        this.form.get('email')?.setErrors({ alreadyRegistered: true });
                        // Don't show alert for email errors, as we're displaying inline
                    } else {
                        // Only show alert for non-email related errors
                        this.alertService.error(errorMessage);
                    }
                    
                    this.loading = false;
                }
            });
    }
    
    isFieldInvalid(fieldName: string): boolean {
        const field = this.form.get(fieldName);
        return field ? (field.invalid && (field.dirty || field.touched || this.submitted)) : false;
    }
}
