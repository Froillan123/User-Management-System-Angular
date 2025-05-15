import { Component, OnInit } from '@angular/core';
import { first } from 'rxjs/operators';

import { RequestService, AlertService, AccountService } from '@app/_services';
import { Request } from '@app/_models/request';

@Component({ templateUrl: 'list.component.html' })
export class ListComponent implements OnInit {
    requests: Request[] = [];
    loading = false;
    account: any;

    constructor(
        private requestService: RequestService,
        private accountService: AccountService,
        private alertService: AlertService
    ) {}

    ngOnInit() {
        this.accountService.account.subscribe(x => {
            this.account = x;
            this.loadRequests();
        });
    }

    deleteRequest(id: number) {
        const request = this.requests.find(x => x.id === id);
        if (!request) return;
        
        request.isDeleting = true;
        this.requestService.delete(id)
            .pipe(first())
            .subscribe(() => {
                this.alertService.success('Request deleted successfully');
                this.requests = this.requests.filter(x => x.id !== id);
            });
    }

    private loadRequests() {
        this.loading = true;
        this.requestService.getAll()
            .pipe(first())
            .subscribe({
                next: requests => {
                    this.loading = false;
                    this.requests = requests;
                },
                error: error => {
                    this.loading = false;
                    this.alertService.error(error);
                }
            });
    }
} 