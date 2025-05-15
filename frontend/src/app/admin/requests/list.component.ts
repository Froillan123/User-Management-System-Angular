import { Component, OnInit } from '@angular/core';
import { first } from 'rxjs/operators';

import { RequestService } from '../../_services';
import { Request } from '../../_models/request';

@Component({ templateUrl: 'list.component.html' })
export class ListComponent implements OnInit {
    requests: Request[] = [];
    pagedRequests: Request[] = [];
    loading = false;
    
    // Pagination
    currentPage = 0;
    pageSize = 5;
    totalPages = 0;
    
    constructor(private requestService: RequestService) {}
    
    ngOnInit() {
        this.loadRequests();
    }
    
    loadRequests() {
        this.loading = true;
        this.requestService.getAll()
            .pipe(first())
            .subscribe({
                next: requests => {
                    console.log('Loaded requests:', requests);
                    this.requests = requests;
                    this.totalPages = Math.ceil(this.requests.length / this.pageSize);
                    this.setPage(0);
                    this.loading = false;
                },
                error: error => {
                    console.error('Error loading requests:', error);
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
        const end = Math.min(start + this.pageSize, this.requests.length);
        this.pagedRequests = this.requests.slice(start, end);
    }
    
    deleteRequest(id: number) {
        const request = this.requests.find(x => x.id === id);
        if (!request) return;
        
        request.isDeleting = true;
        this.requestService.delete(id)
            .pipe(first())
            .subscribe({
                next: () => {
                    this.requests = this.requests.filter(x => x.id !== id);
                    this.totalPages = Math.ceil(this.requests.length / this.pageSize);
                    
                    // If current page is now empty and not the first page, go to previous page
                    if (this.currentPage > 0 && this.currentPage >= this.totalPages) {
                        this.setPage(this.currentPage - 1);
                    } else {
                        this.setPage(this.currentPage);
                    }
                },
                error: error => {
                    console.error('Error deleting request:', error);
                    request.isDeleting = false;
                }
            });
    }
    
    getBadgeClass(status: string) {
        switch (status) {
            case 'Approved': return 'bg-success';
            case 'Rejected': return 'bg-danger';
            default: return 'bg-warning';
        }
    }
} 