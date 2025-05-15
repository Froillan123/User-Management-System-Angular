import { Injectable } from '@angular/core';
import { HttpRequest, HttpHandler, HttpEvent, HttpInterceptor, HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';

import { AccountService } from '../_services';

@Injectable()
export class ErrorInterceptor implements HttpInterceptor {
    constructor(private accountService: AccountService) {}

    intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
        return next.handle(request).pipe(
            catchError((error: HttpErrorResponse) => {
                // Check if the request is a refresh token request
                const isRefreshTokenRequest = request.url.includes('/refresh-token');
                const isAuthRequest = request.url.includes('/authenticate');
                
                // Don't logout for API calls to non-account endpoints
                const isAccountEndpoint = request.url.includes('/accounts/');
                
                if ([401, 403].includes(error.status)) {
                    // Auto logout if 401/403 response but only for account endpoints, not for:
                    // 1. login/authentication requests
                    // 2. refresh token requests
                    // 3. regular API endpoints (non-account endpoints)
                    if (error.status === 401 && !isAuthRequest && !isRefreshTokenRequest && isAccountEndpoint) {
                        console.log('401 error for account endpoint, logging out');
                        this.accountService.logout();
                    } else {
                        console.log('401 error for API endpoint, not logging out');
                    }

                    const errorMessage = error.error?.message || 'Unauthorized access';
                    return throwError(() => new Error(errorMessage));
                }

                if (error.status === 404) {
                    console.log('Request completed:', request.method, request.url);
                    return throwError(() => new Error('Resource not found'));
                }

                if (error.status === 400) {
                    // Handle validation errors
                    if (error.error?.errors) {
                        const validationErrors = Object.values(error.error.errors).join(', ');
                        return throwError(() => new Error(validationErrors));
                    }
                    return throwError(() => new Error(error.error?.message || 'Bad request'));
                }

                // Handle network errors
                if (error.status === 0) {
                    return throwError(() => new Error('Network error. Please check your connection and try again.'));
                }

                // Handle server errors
                if (error.status >= 500) {
                    return throwError(() => new Error('Server error. Please try again later.'));
                }

                // Default error message
                console.log('Error details:', error.error);
                const errorMessage = error.error?.message || error.statusText || 'Something went wrong';
                return throwError(() => new Error(errorMessage));
            })
        );
    }
}
