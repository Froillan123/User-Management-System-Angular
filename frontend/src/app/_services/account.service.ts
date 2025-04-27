import { Injectable } from '@angular/core';
import { Router } from '@angular/router';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { BehaviorSubject, Observable, catchError, throwError, switchMap } from 'rxjs';
import { map, finalize } from 'rxjs/operators';

import { environment } from '../../environments/environment';
import { Account } from '../../app/_models';

const baseUrl = `${environment.apiUrl}/accounts`;

@Injectable({ providedIn: 'root' })
export class AccountService {
  private accountSubject: BehaviorSubject<Account | null>;
  public account: Observable<Account | null>;

  constructor(
    private router: Router,
    private http: HttpClient
  ) {
    const storedAccount = localStorage.getItem('account');
    this.accountSubject = new BehaviorSubject<Account | null>(storedAccount ? JSON.parse(storedAccount) : null);
    this.account = this.accountSubject.asObservable();
  }

  public get accountValue(): Account | null {
    return this.accountSubject.value;
  }

  private getHttpOptions() {
    const account = this.accountValue;
    if (!account?.jwtToken) {
      this.cleanupAndRedirect();
      return {};
    }
    return {
      headers: new HttpHeaders({
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${account.jwtToken}`
      }),
      withCredentials: true
    };
  }

  login(email: string, password: string) {
    return this.http.post<any>(`${baseUrl}/authenticate`, { email, password }, { withCredentials: true })
      .pipe(
        map(account => {
          if (!account || !account.jwtToken) {
            console.error('Invalid login response:', account);
            throw new Error('Invalid login response');
          }
          
          // Store the account info in memory and localStorage
          this.accountSubject.next(account);
          localStorage.setItem('account', JSON.stringify(account));
          
          // Log successful authentication
          console.log('Authentication successful for user:', account.email);
          
          // Start the refresh token timer
          this.startRefreshTokenTimer();
          
          return account;
        }),
        catchError(error => {
          console.error('Login failed:', error);
          // Transform the error to a more user-friendly message
          let errorMsg = 'Login failed';
          if (error.error && error.error.message) {
            errorMsg = error.error.message;
          } else if (error.message) {
            errorMsg = error.message;
          }
          return throwError(() => new Error(errorMsg));
        })
      );
  }

  logout() {
    const refreshToken = this.accountValue?.refreshToken;
    if (refreshToken) {
      // First try to revoke the token
      this.http.post<any>(`${baseUrl}/revoke-token`, { token: refreshToken }, { withCredentials: true })
        .subscribe({
          next: () => {
            this.cleanupAndRedirect();
          },
          error: (error) => {
            console.error('Token revocation failed:', error);
            // Even if revocation fails, we should still clean up and redirect
            this.cleanupAndRedirect();
          }
        });
    } else {
      this.cleanupAndRedirect();
    }
  }

  private cleanupAndRedirect() {
    this.stopRefreshTokenTimer();
    this.accountSubject.next(null);
    localStorage.removeItem('account');
    this.router.navigate(['/account/login']);
  }

  refreshToken() {
    const refreshToken = this.accountValue?.refreshToken;
    if (!refreshToken) {
      console.error('No refresh token available');
      this.cleanupAndRedirect();
      return new Observable();
    }

    return this.http.post<any>(`${baseUrl}/refresh-token`, { refreshToken }, { 
      withCredentials: true,
      headers: new HttpHeaders({
        'Content-Type': 'application/json'
      })
    })
      .pipe(
        map((account) => {
          if (!account || !account.jwtToken) {
            console.error('Invalid refresh token response:', account);
            throw new Error('Invalid refresh token response');
          }
          console.log('Token refreshed successfully');
          
          // Update stored account
          this.accountSubject.next(account);
          localStorage.setItem('account', JSON.stringify(account));
          
          // Restart the refresh timer
          this.startRefreshTokenTimer();
          
          return account;
        }),
        catchError(error => {
          console.error('Token refresh failed:', error);
          this.cleanupAndRedirect();
          return throwError(() => new Error('Session expired. Please login again.'));
        })
      );
  }

  register(account: Account) {
    return this.http.post(`${baseUrl}/register`, account, { withCredentials: true });
  }

  verifyEmail(token: string) {
    return this.http.post(`${baseUrl}/verify-email`, { token }, { withCredentials: true });
  }

  forgotPassword(email: string) {
    return this.http.post(`${baseUrl}/forgot-password`, { email }, { withCredentials: true });
  }

  validateResetToken(token: string) {
    return this.http.post(`${baseUrl}/validate-reset-token`, { token }, { withCredentials: true });
  }

  resetPassword(token: string, password: string, confirmPassword: string) {
    return this.http.post(`${baseUrl}/reset-password`, { token, password, confirmPassword }, { withCredentials: true });
  }

  getAll() {
    const account = this.accountValue;
    const headers = new HttpHeaders({
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${account?.jwtToken}`
    });
    
    return this.http.get<Account[]>(baseUrl, { 
      headers: headers,
      withCredentials: true 
    });
  }

  getById(id: string) {
    const account = this.accountValue;
    const headers = new HttpHeaders({
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${account?.jwtToken}`
    });
    
    return this.http.get<Account>(`${baseUrl}/${id}`, { 
      headers: headers,
      withCredentials: true 
    });
  }

  create(params) {
    const account = this.accountValue;
    const headers = new HttpHeaders({
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${account?.jwtToken}`
    });
    
    return this.http.post(baseUrl, params, { 
      headers: headers,
      withCredentials: true 
    });
  }

  update(id, params) {
    console.log(`Updating account ID ${id} with params:`, params);
    
    const account = this.accountValue;
    if (!account || !account.jwtToken) {
      console.error('No account or token available for update operation');
      return throwError(() => new Error('Authentication required'));
    }
    
    const headers = new HttpHeaders({
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${account.jwtToken}`
    });
    
    console.log(`Using token for update: ${account.jwtToken.substring(0, 20)}...`);
    
    return this.http.put(`${baseUrl}/${id}`, params, {
      headers: headers,
      withCredentials: true
    }).pipe(
      map((updatedAccount: any) => {
        console.log('Update successful, server response:', updatedAccount);
        
        // If updating the current user, update stored user data
        if (updatedAccount.id === this.accountValue?.id) {
          const mergedAccount = { ...this.accountValue, ...updatedAccount };
          console.log('Updating current user data:', mergedAccount);
          
          this.accountSubject.next(mergedAccount);
          localStorage.setItem('account', JSON.stringify(mergedAccount));
        }
        
        return updatedAccount;
      }),
      catchError(error => {
        console.error('Update failed:', error);
        let errorMsg = 'Update failed';
        
        if (error.status === 401) {
          // Handle authentication error - try to refresh token
          console.log('Authentication error during update, attempting refresh');
          return this.refreshToken().pipe(
            switchMap(() => this.update(id, params))
          );
        }
        
        // Transform the error to a more user-friendly message
        if (error.error && error.error.message) {
          errorMsg = error.error.message;
        } else if (error.message) {
          errorMsg = error.message;
        }
        
        return throwError(() => new Error(errorMsg));
      })
    );
  }

  delete(id: string) {
    const account = this.accountValue;
    const headers = new HttpHeaders({
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${account?.jwtToken}`
    });
    
    return this.http.delete(`${baseUrl}/${id}`, {
      headers: headers,
      withCredentials: true
    }).pipe(
      finalize(() => {
        if (id === this.accountValue?.id) {
          this.logout();
        }
      })
    );
  }

  // helper methods

  private refreshTokenTimeout: any;

  private startRefreshTokenTimer() {
    const account = this.accountValue;
    if (!account?.jwtToken) {
      this.logout();
      return;
    }

    try {
      const jwtToken = JSON.parse(atob(account.jwtToken.split('.')[1]));
      const expires = new Date(jwtToken.exp * 1000);
      const timeout = expires.getTime() - Date.now() - (60 * 1000);
      
      if (timeout <= 0) {
        this.logout();
        return;
      }
      
      this.refreshTokenTimeout = setTimeout(() => this.refreshToken().subscribe(), timeout);
    } catch (error) {
      console.error('Error parsing JWT token:', error);
      this.logout();
    }
  }

  private stopRefreshTokenTimer() {
    clearTimeout(this.refreshTokenTimeout);
  }
}
