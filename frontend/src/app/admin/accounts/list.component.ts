import { Component, OnInit } from '@angular/core';
import { first } from 'rxjs/operators';
import { Router } from '@angular/router';

import { AccountService } from '../../../app/_services';
import { Role } from '../../../app/_models';

@Component({ templateUrl: 'list.component.html' })
export class ListComponent implements OnInit {
    accounts: any[] = [];
    filteredAccounts: any[] = [];
    loading = true;
    error = '';

    constructor(
        private accountService: AccountService,
        private router: Router
    ) {
        // Redirect to home if not admin
        if (this.accountService.accountValue?.role !== Role.Admin) {
            this.router.navigate(['/']);
        }
    }

    ngOnInit() {
        this.loadAccounts();
    }

    private loadAccounts() {
        this.loading = true;
        this.error = '';
        
        this.accountService.getAll()
            .pipe(first())
            .subscribe({
                next: accounts => {
                    this.accounts = accounts;
                    this.filteredAccounts = accounts;
                    this.loading = false;
                },
                error: error => {
                    console.error('Error loading accounts:', error);
                    this.error = error;
                    this.loading = false;
                    
                    // If unauthorized, redirect to login
                    if (error === 'Unauthorized') {
                        this.accountService.logout();
                    }
                }
            });
    }

    onSearch(term: string) {
        term = term.toLowerCase();
        this.filteredAccounts = this.accounts.filter(account =>
            (`${account.title} ${account.firstName} ${account.lastName}`.toLowerCase().includes(term) ||
            (account.email && account.email.toLowerCase().includes(term)) ||
            (account.firstName && account.firstName.toLowerCase().includes(term)))
        );
    }
}
