import { Component, OnInit, OnDestroy } from '@angular/core';
import { AccountService } from '../../_services';
import { SocketService } from '../../_services/socket.service';
import { first } from 'rxjs/operators';
import { Account } from '../../_models';
import { Subscription } from 'rxjs';

@Component({
    selector: 'app-users-online',
    templateUrl: 'users-online.component.html'
})
export class UsersOnlineComponent implements OnInit, OnDestroy {
    accounts: Account[] = [];
    loading = true;
    socketSubscription: Subscription;
    statusUpdatesSubscription: Subscription;
    currentPage = 1;
    itemsPerPage = 5;
    totalPages = 1;
    Math = Math; // Make Math available in template
    
    constructor(
        private accountService: AccountService,
        private socketService: SocketService
    ) {}
    
    ngOnInit() {
        this.loadAccounts();
        this.setupSocketListeners();
    }
    
    ngOnDestroy() {
        if (this.socketSubscription) {
            this.socketSubscription.unsubscribe();
        }
        
        if (this.statusUpdatesSubscription) {
            this.statusUpdatesSubscription.unsubscribe();
        }
    }
    
    private loadAccounts() {
        this.loading = true;
        this.accountService.getAll()
            .pipe(first())
            .subscribe({
                next: accounts => {
                    // Sort accounts to show online users first
                    this.accounts = accounts.sort((a, b) => {
                        if (a.isOnline && !b.isOnline) return -1;
                        if (!a.isOnline && b.isOnline) return 1;
                        return 0;
                    });
                    this.totalPages = Math.ceil(this.accounts.length / this.itemsPerPage);
                    this.loading = false;
                },
                error: error => {
                    console.error('Error loading accounts:', error);
                    this.loading = false;
                }
            });
    }
    
    private setupSocketListeners() {
        // Listen for user status updates
        this.socketSubscription = this.socketService.getUserStatusUpdates().subscribe(update => {
            const account = this.accounts.find(a => a.id === update.userId);
            if (account) {
                account.isOnline = update.isOnline;
                // Re-sort accounts to maintain online users first
                this.accounts.sort((a, b) => {
                    if (a.isOnline && !b.isOnline) return -1;
                    if (!a.isOnline && b.isOnline) return 1;
                    return 0;
                });
            }
        });
    }
    
    get paginatedAccounts() {
        const startIndex = (this.currentPage - 1) * this.itemsPerPage;
        return this.accounts.slice(startIndex, startIndex + this.itemsPerPage);
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
    
    // Helper methods for the template
    getOnlineUsersCount(): number {
        return this.accounts.filter(a => a.isOnline).length;
    }
    
    getOfflineUsersCount(): number {
        return this.accounts.filter(a => !a.isOnline).length;
    }
    
    getTotalUsersCount(): number {
        return this.accounts.length;
    }
    
    isAdminRole(role: string): boolean {
        return role === 'Admin';
    }
    
    isUserRole(role: string): boolean {
        return role === 'User';
    }
} 