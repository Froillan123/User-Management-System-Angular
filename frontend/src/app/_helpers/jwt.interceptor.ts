import { Injectable } from '@angular/core';
import { HttpRequest, HttpHandler, HttpEvent, HttpInterceptor, HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError, BehaviorSubject } from 'rxjs';
import { catchError, filter, take, switchMap, finalize } from 'rxjs/operators';

import { environment } from '../../environments/environment';
import { AccountService } from '../_services';

@Injectable()
export class JwtInterceptor implements HttpInterceptor {
  private isRefreshing = false;
  private refreshTokenSubject: BehaviorSubject<any> = new BehaviorSubject<any>(null);

  constructor(private accountService: AccountService) { }

  intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    // add auth header with jwt if account is logged in and request is to the api url
    const account = this.accountService.accountValue;
    const isLoggedIn = account?.jwtToken;
    
    // Check if request is to any of our API endpoints
    const isApiUrl = request.url.includes(environment.apiUrl) || 
                    request.url.includes('user-management-system-angular.onrender.com') ||
                    request.url.includes('user-management-system-angular-tm8z.vercel.app') ||
                    request.url.includes('localhost:4000');
                    
    const isRefreshTokenRequest = request.url.includes('/refresh-token');
    const isRevokeTokenRequest = request.url.includes('/revoke-token');
    const isAuthenticateRequest = request.url.includes('/authenticate');

    // Don't add token to authentication-related requests
    if (isLoggedIn && isApiUrl && !isRefreshTokenRequest && !isRevokeTokenRequest && !isAuthenticateRequest) {
      console.log(`Adding auth header to request: ${request.method} ${request.url}`);
      
      // Clone request with Authorization header
      request = request.clone({
        setHeaders: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${account.jwtToken}`
        },
        withCredentials: true
      });
    } else {
      // Always ensure all API requests include credentials
      if (isApiUrl) {
        console.log(`Request without auth header but with credentials: ${request.method} ${request.url}`);
        request = request.clone({
          withCredentials: true
        });
      }
    }

    return next.handle(request).pipe(
      catchError((error: HttpErrorResponse) => {
        if ([401, 403].includes(error.status) && !isRefreshTokenRequest && !isRevokeTokenRequest && !isAuthenticateRequest) {
          console.log(`${error.status} error detected, attempting token refresh`);
          return this.handle401Error(request, next);
        }
        
        // Enhanced error logging
        if (error.error instanceof ErrorEvent) {
          // Client-side error
          console.error(`Client-side error: ${error.error.message}`);
        } else {
          // Server-side error
          console.error(`Server-side error: ${error.status} ${error.statusText}`);
          console.error('Error details:', error.error);
        }
        
        return throwError(() => error);
      }),
      finalize(() => {
        // Log when requests complete
        console.log(`Request completed: ${request.method} ${request.url}`);
      })
    );
  }

  private handle401Error(request: HttpRequest<any>, next: HttpHandler) {
    if (!this.isRefreshing) {
      this.isRefreshing = true;
      this.refreshTokenSubject.next(null);

      console.log('Refreshing access token...');
      
      // Try to refresh token
      return this.accountService.refreshToken().pipe(
        switchMap((account) => {
          console.log('Token refresh successful, retrying original request');
          this.isRefreshing = false;
          this.refreshTokenSubject.next(account);
          
          // Create a new request with the new token
          const newRequest = this.addTokenHeader(request, account.jwtToken);
          return next.handle(newRequest);
        }),
        catchError((err) => {
          console.error('Token refresh failed, logging out user:', err);
          this.isRefreshing = false;
          this.accountService.logout();
          return throwError(() => new Error('Session expired. Please login again.'));
        }),
        finalize(() => {
          this.isRefreshing = false;
        })
      );
    }

    console.log('Waiting for token refresh to complete');
    
    // Wait for the token to be refreshed
    return this.refreshTokenSubject.pipe(
      filter(token => token != null),
      take(1),
      switchMap(account => {
        console.log('Using newly refreshed token for request');
        const newRequest = this.addTokenHeader(request, account.jwtToken);
        return next.handle(newRequest);
      })
    );
  }

  private addTokenHeader(request: HttpRequest<any>, token: string) {
    console.log(`Adding refreshed token to request: ${request.method} ${request.url}`);
    console.log(`New JWT token: ${token.substring(0, 20)}...`);
    
    return request.clone({
      setHeaders: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      withCredentials: true
    });
  }
}
