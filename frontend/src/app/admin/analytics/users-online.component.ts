import { Component, OnInit, OnDestroy } from '@angular/core';
import { AccountService } from '../../_services';
import { SocketService } from '../../_services/socket.service';
import { first } from 'rxjs/operators';
import { Account } from '../../_models';
import { Subscription } from 'rxjs';

@Component({
    selector: 'app-users-online',
    templateUrl: './users-online.component.html',
    styles: [`
        .card {
            border-radius: 12px;
            transition: all 0.3s ease;
            border: none;
            box-shadow: 0 4px 12px rgba(0,0,0,0.05);
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 16px rgba(0,0,0,0.1);
        }
        
        .table thead th {
            cursor: pointer;
            user-select: none;
        }
        
        .table thead th:hover {
            background-color: rgba(0,0,0,0.05);
        }
        
        .table-responsive {
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
        }
        
        @media (max-width: 768px) {
            .table td {
                padding: 0.5rem;
            }
        }
    `]
})
export class UsersOnlineComponent implements OnInit, OnDestroy {
    users: any[] = [];
    filteredUsers: any[] = [];
    loading = false;
    subscription: Subscription;
    socketSubscription: Subscription;
    statusUpdatesSubscription: Subscription;
    currentPage = 1;
    itemsPerPage = 5;
    totalPages = 1;
    Math = Math; // Make Math available in template
    
    // Sorting
    sortColumn = 'lastActive';
    sortDirection = 'desc';
    
    // Filtering
    searchTerm = '';
    statusFilter = 'all';
    roleFilter = 'all';
    
    constructor(
        private accountService: AccountService,
        private socketService: SocketService
    ) {}
    
    ngOnInit() {
        this.loadUsers();
        this.setupSocketListeners();
    }
    
    ngOnDestroy() {
        if (this.subscription) {
            this.subscription.unsubscribe();
        }
        
        if (this.socketSubscription) {
            this.socketSubscription.unsubscribe();
        }
        
        if (this.statusUpdatesSubscription) {
            this.statusUpdatesSubscription.unsubscribe();
        }
    }
    
    loadUsers() {
        this.loading = true;
        this.accountService.getAll()
            .pipe(first())
            .subscribe({
                next: users => {
                    this.users = users;
                    this.filteredUsers = [...users];
                    this.totalPages = Math.ceil(this.users.length / this.itemsPerPage);
                    this.sort(this.sortColumn);
                    this.loading = false;
                },
                error: error => {
                    console.error('Error loading users:', error);
                    this.loading = false;
                }
            });
    }
    
    setupSocketListeners() {
        // Listen for user status updates
        this.socketSubscription = this.socketService.getUserStatusUpdates().subscribe(update => {
            const user = this.users.find(u => u.id === update.userId);
            if (user) {
                user.isOnline = update.isOnline;
                // Re-sort users to maintain online users first
                this.filteredUsers.sort((a, b) => {
                    if (a.isOnline && !b.isOnline) return -1;
                    if (!a.isOnline && b.isOnline) return 1;
                    return 0;
                });
            }
        });
    }
    
    get paginatedUsers() {
        const startIndex = (this.currentPage - 1) * this.itemsPerPage;
        return this.filteredUsers.slice(startIndex, startIndex + this.itemsPerPage);
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
        return this.filteredUsers.filter(u => u.isOnline).length;
    }
    
    getOfflineUsersCount(): number {
        return this.filteredUsers.filter(u => !u.isOnline).length;
    }
    
    getTotalUsersCount(): number {
        return this.filteredUsers.length;
    }
    
    isAdminRole(role: string): boolean {
        return role === 'Admin';
    }
    
    isUserRole(role: string): boolean {
        return role === 'User';
    }
    
    sort(column: string) {
        if (this.sortColumn === column) {
            this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
        } else {
            this.sortColumn = column;
            this.sortDirection = 'asc';
        }
        
        this.filteredUsers.sort((a, b) => {
            const valueA = a[column];
            const valueB = b[column];
            
            if (column === 'lastActive') {
                const dateA = valueA ? new Date(valueA).getTime() : 0;
                const dateB = valueB ? new Date(valueB).getTime() : 0;
                return this.sortDirection === 'asc' ? dateA - dateB : dateB - dateA;
            }
            
            if (typeof valueA === 'boolean') {
                return this.sortDirection === 'asc' 
                    ? (valueA === valueB ? 0 : valueA ? -1 : 1)
                    : (valueA === valueB ? 0 : valueA ? 1 : -1);
            }
            
            if (valueA === valueB) return 0;
            
            const comparison = valueA > valueB ? 1 : -1;
            return this.sortDirection === 'asc' ? comparison : -comparison;
        });
    }
    
    applyFilters() {
        this.filteredUsers = this.users.filter(user => {
            // Search term filter
            const searchMatch = !this.searchTerm || 
                user.firstName.toLowerCase().includes(this.searchTerm.toLowerCase()) || 
                user.lastName.toLowerCase().includes(this.searchTerm.toLowerCase()) || 
                user.email.toLowerCase().includes(this.searchTerm.toLowerCase());
            
            // Status filter
            const statusMatch = this.statusFilter === 'all' || 
                (this.statusFilter === 'online' && user.isOnline) || 
                (this.statusFilter === 'offline' && !user.isOnline);
                
            // Role filter
            const roleMatch = this.roleFilter === 'all' || user.role === this.roleFilter;
            
            return searchMatch && statusMatch && roleMatch;
        });
        
        // Keep the current sort
        this.sort(this.sortColumn);
    }
    
    resetFilters() {
        this.searchTerm = '';
        this.statusFilter = 'all';
        this.roleFilter = 'all';
        this.filteredUsers = [...this.users];
        this.sort(this.sortColumn);
    }
    
    exportCSV() {
        if (!this.filteredUsers.length) return;
        
        const headers = ['First Name', 'Last Name', 'Email', 'Role', 'Status', 'Last Active'];
        const csvRows: string[] = [];
        
        // Add headers
        csvRows.push(headers.join(','));
        
        // Add data rows
        for (const user of this.filteredUsers) {
            const row = [
                user.firstName,
                user.lastName,
                user.email,
                user.role,
                user.isOnline ? 'Online' : 'Offline',
                user.lastActive ? new Date(user.lastActive).toLocaleString() : 'Never'
            ];
            
            // Escape any commas in the data
            const escapedRow = row.map(field => {
                return `"${String(field).replace(/"/g, '""')}"`;
            });
            
            csvRows.push(escapedRow.join(','));
        }
        
        // Create and download the CSV file
        const csvContent = csvRows.join('\n');
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        
        const link = document.createElement('a');
        link.setAttribute('href', url);
        link.setAttribute('download', `users-${new Date().toISOString().split('T')[0]}.csv`);
        link.style.visibility = 'hidden';
        
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }
} 