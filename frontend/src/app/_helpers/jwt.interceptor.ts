import { Injectable } from '@angular/core';
import { HttpRequest, HttpHandler, HttpEvent, HttpInterceptor, HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError, BehaviorSubject } from 'rxjs';
import { catchError, filter, take, switchMap } from 'rxjs/operators';

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
    const isApiUrl = request.url.startsWith(environment.apiUrl);
    const isRefreshTokenRequest = request.url.includes('/refresh-token');
    const isRevokeTokenRequest = request.url.includes('/revoke-token');
    const isAuthenticateRequest = request.url.includes('/authenticate');

    // Don't add token to authentication-related requests
    if (isLoggedIn && isApiUrl && !isRefreshTokenRequest && !isRevokeTokenRequest && !isAuthenticateRequest) {
      console.log(`Adding auth header to request: ${request.method} ${request.url}`);
      
      request = request.clone({
        setHeaders: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${account.jwtToken}`
        },
        withCredentials: true
      });
    }

    return next.handle(request).pipe(
      catchError((error: HttpErrorResponse) => {
        if (error.status === 401 && !isRefreshTokenRequest && !isRevokeTokenRequest && !isAuthenticateRequest) {
          console.log('401 error detected, attempting token refresh');
          return this.handle401Error(request, next);
        }
        
        // Log the error and pass it on
        console.error(`HTTP Error: ${error.status}`, error);
        return throwError(() => error);
      })
    );
  }

  private handle401Error(request: HttpRequest<any>, next: HttpHandler) {
    if (!this.isRefreshing) {
      this.isRefreshing = true;
      this.refreshTokenSubject.next(null);

      return this.accountService.refreshToken().pipe(
        switchMap((account) => {
          this.isRefreshing = false;
          this.refreshTokenSubject.next(account);
          return next.handle(this.addTokenHeader(request, account.jwtToken));
        }),
        catchError((err) => {
          this.isRefreshing = false;
          this.accountService.logout();
          return throwError(() => err);
        })
      );
    }

    return this.refreshTokenSubject.pipe(
      filter(token => token != null),
      take(1),
      switchMap(account => next.handle(this.addTokenHeader(request, account.jwtToken)))
    );
  }

  private addTokenHeader(request: HttpRequest<any>, token: string) {
    return request.clone({
      setHeaders: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      withCredentials: true
    });
  }
}
