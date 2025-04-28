import { Injectable } from '@angular/core';
import { Observable, BehaviorSubject, Subject } from 'rxjs';
import { map } from 'rxjs/operators';
import { Account } from '../_models';
import { io, Socket } from 'socket.io-client';
import { environment } from '../../environments/environment';

@Injectable({
  providedIn: 'root'
})
export class SocketService {
  private socket: Socket | null = null;
  private onlineUsers = new BehaviorSubject<Account[]>([]);
  private registrationStats = new BehaviorSubject<any>({
    monthlyData: [],
    totalRegistrations: 0
  });
  private userStatusUpdates = new Subject<{ userId: string, isOnline: boolean }>();
  
  // Socket status
  private isConnected = false;
  private currentUserId: string = '';
  private jwtToken: string = '';
  private heartbeatInterval: any;

  constructor() {
    // Try to get the current user ID and token from localStorage
    try {
      const accountData = localStorage.getItem('account');
      if (accountData) {
        const account = JSON.parse(accountData);
        this.currentUserId = account.id || '';
        this.jwtToken = account.jwtToken || '';
      }
    } catch (e) {
      console.error('Error getting account from localStorage:', e);
    }
  }

  // Set current user ID and token (call this after login)
  setCurrentUser(userId: string, token: string): void {
    this.currentUserId = userId;
    this.jwtToken = token;
    
    // If connected, disconnect and reconnect with new token
    if (this.isConnected) {
      this.disconnect();
      this.connect();
    }
  }

  // Connect to the WebSocket server
  connect(): void {
    if (this.isConnected || !this.jwtToken) return;
    
    console.log('Socket connecting...');
    
    // Connect to the WebSocket server
    this.socket = io(environment.apiUrl.replace('/accounts', ''), {
      auth: {
        token: this.jwtToken
      },
      withCredentials: true,
      transports: ['websocket', 'polling']
    });
    
    // Handle connection events
    this.socket.on('connect', () => {
      console.log('Socket connected successfully');
      this.isConnected = true;
      
      // Start sending heartbeats every 30 seconds
      this.startHeartbeat();
    });
    
    // Handle online users updates
    this.socket.on('online-users-update', (users: Account[]) => {
      console.log('Received online users update:', users.length);
      this.onlineUsers.next(users);
    });
    
    // Handle user stats updates
    this.socket.on('user-stats-update', (stats: any) => {
      console.log('Received user stats update');
      this.registrationStats.next(stats);
    });
    
    // Handle individual user status changes
    this.socket.on('user-status-change', (update: { userId: string, isOnline: boolean }) => {
      console.log('Received user status change:', update);
      this.userStatusUpdates.next(update);
      
      // Also update in the users array
      const currentUsers = this.onlineUsers.value;
      if (currentUsers.length > 0) {
        const updatedUsers = currentUsers.map(user => {
          if (user.id === update.userId) {
            return { ...user, isOnline: update.isOnline };
          }
          return user;
        });
        this.onlineUsers.next(updatedUsers);
      }
    });
    
    // Handle disconnect
    this.socket.on('disconnect', () => {
      console.log('Socket disconnected');
      this.isConnected = false;
      this.stopHeartbeat();
    });
    
    // Handle connection errors
    this.socket.on('connect_error', (error) => {
      console.error('Socket connection error:', error);
      this.isConnected = false;
    });
  }

  // Disconnect from the WebSocket server
  disconnect(): void {
    if (!this.isConnected || !this.socket) return;
    
    console.log('Socket disconnecting...');
    this.stopHeartbeat();
    this.socket.disconnect();
    this.socket = null;
    this.isConnected = false;
  }

  // Start sending heartbeats
  private startHeartbeat(): void {
    this.stopHeartbeat(); // Clear any existing interval
    this.heartbeatInterval = setInterval(() => {
      if (this.socket && this.isConnected) {
        this.socket.emit('heartbeat');
      }
    }, 30000); // Send heartbeat every 30 seconds
  }

  // Stop sending heartbeats
  private stopHeartbeat(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }

  // Update online users from backend
  updateOnlineUsers(users: Account[]): void {
    // Make sure current user is always shown as online if logged in
    if (this.currentUserId) {
      users = users.map(user => {
        if (user.id === this.currentUserId) {
          return {
            ...user,
            isOnline: true,
            lastActive: new Date()
          };
        }
        return user;
      });
    }
    
    this.onlineUsers.next(users);
  }

  // Update registration stats
  updateRegistrationStats(stats: any): void {
    this.registrationStats.next(stats);
  }

  // Get online users as observable
  getOnlineUsers(): Observable<Account[]> {
    // Request online users update if connected
    if (this.socket && this.isConnected) {
      this.socket.emit('get-online-users');
    }
    return this.onlineUsers.asObservable();
  }

  // Get registration stats as observable
  getRegistrationStats(): Observable<any> {
    // Request stats update if connected
    if (this.socket && this.isConnected) {
      this.socket.emit('get-user-stats');
    }
    return this.registrationStats.asObservable();
  }

  // Get single user status changes
  getUserStatusUpdates(): Observable<{ userId: string, isOnline: boolean }> {
    return this.userStatusUpdates.asObservable();
  }

  // Helper method to get current online count
  getOnlineCount(): Observable<number> {
    return this.onlineUsers.pipe(
      map(users => users.filter(u => u.isOnline).length)
    );
  }

  // Helper method to get current offline count
  getOfflineCount(): Observable<number> {
    return this.onlineUsers.pipe(
      map(users => users.filter(u => !u.isOnline).length)
    );
  }
} 