import { Injectable } from '@angular/core';
import { Router } from '@angular/router';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { BehaviorSubject, Observable, catchError, throwError } from 'rxjs';
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
    return {
      headers: new HttpHeaders({
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${account?.jwtToken || ''}`
      }),
      withCredentials: true
    };
  }

  login(email: string, password: string) {
    return this.http.post<any>(`${baseUrl}/authenticate`, { email, password }, this.getHttpOptions())
      .pipe(map(account => {
        this.accountSubject.next(account);
        localStorage.setItem('account', JSON.stringify(account));
        this.startRefreshTokenTimer();
        return account;
      }));
  }

  logout() {
    const refreshToken = this.accountValue?.refreshToken;
    if (refreshToken) {
      // First try to revoke the token
      this.http.post<any>(`${baseUrl}/revoke-token`, { token: refreshToken }, this.getHttpOptions())
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
      this.cleanupAndRedirect();
      return new Observable();
    }

    return this.http.post<any>(`${baseUrl}/refresh-token`, { token: refreshToken }, this.getHttpOptions())
      .pipe(
        map((account) => {
          if (!account || !account.jwtToken) {
            throw new Error('Invalid refresh token response');
          }
          this.accountSubject.next(account);
          localStorage.setItem('account', JSON.stringify(account));
          this.startRefreshTokenTimer();
          return account;
        }),
        catchError(error => {
          console.error('Token refresh failed:', error);
          this.cleanupAndRedirect();
          return throwError(() => error);
        })
      );
  }

  register(account: Account) {
    return this.http.post(`${baseUrl}/register`, account, this.getHttpOptions());
  }

  verifyEmail(token: string) {
    return this.http.post(`${baseUrl}/verify-email`, { token }, this.getHttpOptions());
  }

  forgotPassword(email: string) {
    return this.http.post(`${baseUrl}/forgot-password`, { email }, this.getHttpOptions());
  }

  validateResetToken(token: string) {
    return this.http.post(`${baseUrl}/validate-reset-token`, { token }, this.getHttpOptions());
  }

  resetPassword(token: string, password: string, confirmPassword: string) {
    return this.http.post(`${baseUrl}/reset-password`, { token, password, confirmPassword }, this.getHttpOptions());
  }

  getAll() {
    return this.http.get<Account[]>(baseUrl, this.getHttpOptions());
  }

  getById(id: string) {
    return this.http.get<Account>(`${baseUrl}/${id}`, this.getHttpOptions());
  }

  create(params) {
    return this.http.post(baseUrl, params, this.getHttpOptions());
  }

  update(id, params) {
    return this.http.put(`${baseUrl}/${id}`, params, this.getHttpOptions())
      .pipe(map((account: any) => {
        if (account.id === this.accountValue?.id) {
          account = { ...this.accountValue, ...account };
          this.accountSubject.next(account);
          localStorage.setItem('account', JSON.stringify(account));
        }
        return account;
      }));
  }

  delete(id: string) {
    return this.http.delete(`${baseUrl}/${id}`, this.getHttpOptions())
      .pipe(finalize(() => {
        if (id === this.accountValue?.id) {
          this.logout();
        }
      }));
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
