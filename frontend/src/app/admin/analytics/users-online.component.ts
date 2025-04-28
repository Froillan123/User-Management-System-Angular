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
    
    constructor(
        private accountService: AccountService,
        private socketService: SocketService
    ) {}
    
    ngOnInit() {
        // Initial load of users
        this.loadUsers();
        
        // Connect to socket service if not already connected
        this.socketService.connect();
        
        // Subscribe to socket service for real-time updates on all users
        this.socketSubscription = this.socketService.getOnlineUsers()
            .subscribe(users => {
                if (users && users.length > 0) {
                    this.accounts = users;
                    this.loading = false;
                }
            });
        
        // Subscribe to individual user status updates
        this.statusUpdatesSubscription = this.socketService.getUserStatusUpdates()
            .subscribe(update => {
                // Update the status of the specific user
                this.accounts = this.accounts.map(user => {
                    if (user.id === update.userId) {
                        return {
                            ...user,
                            isOnline: update.isOnline
                        };
                    }
                    return user;
                });
            });
    }
    
    ngOnDestroy() {
        if (this.socketSubscription) {
            this.socketSubscription.unsubscribe();
        }
        
        if (this.statusUpdatesSubscription) {
            this.statusUpdatesSubscription.unsubscribe();
        }
    }
    
    loadUsers() {
        this.accountService.getOnlineUsers()
            .pipe(first())
            .subscribe({
                next: accounts => {
                    this.accounts = accounts;
                    this.loading = false;
                    
                    // Update socket service with latest data
                    this.socketService.updateOnlineUsers(accounts);
                },
                error: error => {
                    console.error('Error loading online users:', error);
                    this.loading = false;
                }
            });
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