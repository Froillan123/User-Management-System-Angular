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
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000; // Start with 1 second
  private lastHeartbeat: Date | null = null;

  constructor() {
    // Try to get the current user ID and token from localStorage
    try {
      const accountData = localStorage.getItem('account');
      if (accountData) {
        const account = JSON.parse(accountData);
        this.currentUserId = account.id || '';
        this.jwtToken = account.jwtToken || '';
        
        // If we have credentials, try to connect
        if (this.currentUserId && this.jwtToken) {
          this.connect();
        }
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
    }
    
    // Connect with new credentials
    this.connect();
  }

  // Connect to the WebSocket server
  connect(): void {
    if (this.isConnected || !this.jwtToken) return;
    
    console.log('Socket connecting...');
    
    // Connect to the WebSocket server using the environment URL
    const socketUrl = environment.wsUrl || environment.apiUrl.replace('/accounts', '');
    console.log(`Connecting to WebSocket server at: ${socketUrl}`);
    
    this.socket = io(socketUrl, {
      auth: {
        token: this.jwtToken
      },
      withCredentials: true,
      transports: ['websocket', 'polling'],
      autoConnect: false,
      reconnection: true,
      reconnectionAttempts: this.maxReconnectAttempts,
      reconnectionDelay: this.reconnectDelay,
      reconnectionDelayMax: 5000,
      timeout: 10000
    });
    
    // Connect manually
    this.socket.connect();
    
    // Handle connection events
    this.socket.on('connect', () => {
      console.log('Socket connected successfully');
      this.isConnected = true;
      this.reconnectAttempts = 0;
      this.reconnectDelay = 1000;
      this.lastHeartbeat = new Date();
      
      // Start sending heartbeats every 30 seconds
      this.startHeartbeat();
      
      // Request initial data
      this.requestInitialData();
    });
    
    // Handle online users updates
    this.socket.on('online-users-update', (users: Account[]) => {
      console.log('Received online users update:', users.length);
      // Filter out users who haven't sent a heartbeat in the last 5 minutes
      const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
      const activeUsers = users.filter(user => {
        if (!user.lastActive) return false;
        return new Date(user.lastActive) > fiveMinutesAgo;
      });
      this.onlineUsers.next(activeUsers);
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
      
      // Attempt to reconnect if we haven't exceeded max attempts
      if (this.reconnectAttempts < this.maxReconnectAttempts) {
        this.reconnectAttempts++;
        this.reconnectDelay = Math.min(this.reconnectDelay * 2, 5000); // Exponential backoff
        setTimeout(() => this.connect(), this.reconnectDelay);
      }
    });
    
    // Handle connection errors
    this.socket.on('connect_error', (error) => {
      console.error('Socket connection error:', error);
      this.isConnected = false;
      
      // Attempt to reconnect if we haven't exceeded max attempts
      if (this.reconnectAttempts < this.maxReconnectAttempts) {
        this.reconnectAttempts++;
        this.reconnectDelay = Math.min(this.reconnectDelay * 2, 5000); // Exponential backoff
        setTimeout(() => this.connect(), this.reconnectDelay);
      }
    });
  }

  // Request initial data after connection
  private requestInitialData(): void {
    if (this.socket && this.isConnected) {
      this.socket.emit('get-online-users');
      this.socket.emit('get-user-stats');
    }
  }

  // Disconnect from the WebSocket server
  disconnect(): void {
    if (!this.isConnected || !this.socket) return;
    
    console.log('Socket disconnecting...');
    this.stopHeartbeat();
    this.socket.disconnect();
    this.socket = null;
    this.isConnected = false;
    this.reconnectAttempts = 0;
    this.lastHeartbeat = null;
  }

  // Start sending heartbeats
  private startHeartbeat(): void {
    this.stopHeartbeat(); // Clear any existing interval
    this.heartbeatInterval = setInterval(() => {
      if (this.socket && this.isConnected) {
        this.socket.emit('heartbeat');
        this.lastHeartbeat = new Date();
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
      map(users => {
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
        return users.filter(u => u.isOnline && u.lastActive && new Date(u.lastActive) > fiveMinutesAgo).length;
      })
    );
  }

  // Helper method to get current offline count
  getOfflineCount(): Observable<number> {
    return this.onlineUsers.pipe(
      map(users => {
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
        return users.filter(u => !u.isOnline || !u.lastActive || new Date(u.lastActive) <= fiveMinutesAgo).length;
      })
    );
  }
} 