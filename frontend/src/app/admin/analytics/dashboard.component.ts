import { Component, OnInit, AfterViewInit, ElementRef, ViewChild, OnDestroy } from '@angular/core';
import { AccountService } from '../../_services';
import { SocketService } from '../../_services/socket.service';
import { first } from 'rxjs/operators';
import { Subscription } from 'rxjs';

// Declare Chart.js to avoid TypeScript errors
declare var Chart: any;

@Component({
    selector: 'app-dashboard',
    templateUrl: 'dashboard.component.html'
})
export class DashboardComponent implements OnInit, AfterViewInit, OnDestroy {
    @ViewChild('usersChart') usersChartRef: ElementRef;
    @ViewChild('tokenChart') tokenChartRef: ElementRef;
    
    totalUsers = 0;
    activeUsers = 0;
    onlineUsers = 0;
    verifiedUsers = 0;
    
    monthlyRegistrations: { month: string, count: number, isCurrent?: boolean }[] = [];
    refreshTokens = 0;
    
    loading = true;
    
    // For real-time updates
    usersChart: any;
    tokensChart: any;
    private subscriptions: Subscription[] = [];
    
    constructor(
        private accountService: AccountService,
        private socketService: SocketService
    ) {}
    
    ngOnInit() {
        this.loadStats();
        
        // Connect to "socket"
        this.socketService.connect();
        
        // Subscribe to real-time updates
        this.subscriptions.push(
            this.socketService.getOnlineUsers().subscribe(users => {
                if (users.length > 0) {
                    this.onlineUsers = users.filter(u => u.isOnline).length;
                    // Update the chart if it exists
                    this.updateCharts();
                }
            })
        );
    }
    
    ngAfterViewInit() {
        setTimeout(() => this.initCharts(), 500);
    }
    
    ngOnDestroy() {
        // Disconnect socket
        this.socketService.disconnect();
        
        // Unsubscribe from all subscriptions
        this.subscriptions.forEach(sub => sub.unsubscribe());
    }
    
    loadStats() {
        this.accountService.getUserStats()
            .pipe(first())
            .subscribe(stats => {
                this.totalUsers = stats.totalUsers;
                this.activeUsers = stats.activeUsers;
                this.onlineUsers = stats.onlineUsers;
                this.verifiedUsers = stats.verifiedUsers;
                this.refreshTokens = stats.refreshTokenCount;
                this.monthlyRegistrations = stats.monthlyData;
                
                // Initialize socket service with user data
                this.accountService.getOnlineUsers()
                    .pipe(first())
                    .subscribe(users => {
                        this.socketService.updateOnlineUsers(users);
                        
                        // Update registration stats in socket service
                        this.socketService.updateRegistrationStats({
                            monthlyData: this.monthlyRegistrations,
                            totalRegistrations: this.totalUsers
                        });
                    });
                
                this.loading = false;
                
                // Initialize charts after data is loaded
                this.initCharts();
            });
    }
    
    initCharts() {
        if (this.usersChartRef && this.usersChartRef.nativeElement) {
            const ctx = this.usersChartRef.nativeElement.getContext('2d');
            
            // Create a gradient background for the line
            const gradient = ctx.createLinearGradient(0, 0, 0, 400);
            gradient.addColorStop(0, 'rgba(54, 162, 235, 0.7)');
            gradient.addColorStop(1, 'rgba(54, 162, 235, 0.1)');
            
            this.usersChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: this.monthlyRegistrations.map(item => item.month),
                    datasets: [{
                        label: 'New Users',
                        data: this.monthlyRegistrations.map(item => item.count),
                        backgroundColor: gradient,
                        borderColor: 'rgba(54, 162, 235, 1)',
                        borderWidth: 2,
                        pointBackgroundColor: this.monthlyRegistrations.map(item => 
                            item.isCurrent ? 'rgba(54, 162, 235, 1)' : 'rgba(54, 162, 235, 0.7)'
                        ),
                        pointRadius: this.monthlyRegistrations.map(item => 
                            item.isCurrent ? 5 : 3
                        ),
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    plugins: {
                        legend: {
                            display: false
                        },
                        tooltip: {
                            enabled: true,
                            mode: 'index',
                            intersect: false,
                            backgroundColor: 'rgba(0, 0, 0, 0.7)',
                            titleColor: '#fff',
                            bodyColor: '#fff',
                            titleFont: {
                                size: 14
                            },
                            bodyFont: {
                                size: 14
                            },
                            padding: 12,
                            displayColors: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            grid: {
                                color: 'rgba(200, 200, 200, 0.1)'
                            },
                            ticks: {
                                color: '#6c757d'
                            }
                        },
                        x: {
                            grid: {
                                display: false
                            },
                            ticks: {
                                color: '#6c757d'
                            }
                        }
                    },
                    responsive: true,
                    maintainAspectRatio: false
                }
            });
        }
        
        if (this.tokenChartRef && this.tokenChartRef.nativeElement) {
            const ctx = this.tokenChartRef.nativeElement.getContext('2d');
            this.tokensChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Active Sessions', 'Inactive'],
                    datasets: [{
                        data: [this.refreshTokens, this.totalUsers - this.refreshTokens],
                        backgroundColor: [
                            'rgba(54, 162, 235, 0.8)',
                            'rgba(220, 220, 220, 0.8)'
                        ],
                        borderColor: [
                            'rgba(54, 162, 235, 1)',
                            'rgba(220, 220, 220, 1)'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                padding: 20,
                                boxWidth: 12,
                                color: '#6c757d'
                            }
                        }
                    },
                    cutout: '70%',
                    responsive: true,
                    maintainAspectRatio: false
                }
            });
        }
    }
    
    updateCharts() {
        if (this.tokensChart) {
            // Update the active sessions data
            this.tokensChart.data.datasets[0].data = [this.refreshTokens, this.totalUsers - this.refreshTokens];
            this.tokensChart.update();
        }
    }
} 