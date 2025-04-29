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
    currentPage = 1;
    itemsPerPage = 5;
    totalPages = 1;
    Math = Math; // Make Math available in template

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
                    // Sort accounts to show admins first
                    this.accounts = accounts.sort((a, b) => {
                        if (a.role === Role.Admin && b.role !== Role.Admin) return -1;
                        if (a.role !== Role.Admin && b.role === Role.Admin) return 1;
                        return 0;
                    });
                    this.filteredAccounts = this.accounts;
                    this.totalPages = Math.ceil(this.filteredAccounts.length / this.itemsPerPage);
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
        this.totalPages = Math.ceil(this.filteredAccounts.length / this.itemsPerPage);
        this.currentPage = 1;
    }

    get paginatedAccounts() {
        const startIndex = (this.currentPage - 1) * this.itemsPerPage;
        return this.filteredAccounts.slice(startIndex, startIndex + this.itemsPerPage);
    }

    nextPage() {
        if (this.currentPage < this.totalPages) {
            this.currentPage++;
        }
    }

    previousPage() {
        if (this.currentPage > 1) {
            this.currentPage--;
        }
    }
}
