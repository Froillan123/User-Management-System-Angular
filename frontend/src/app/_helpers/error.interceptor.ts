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
                
                if ([401, 403].includes(error.status)) {
                    // Auto logout if 401/403 response but not for:
                    // 1. login/authentication requests
                    // 2. refresh token requests - JWT interceptor handles these
                    if (error.status === 401 && !isAuthRequest && !isRefreshTokenRequest) {
                        console.log('401 error for non-auth request, logging out');
                        this.accountService.logout();
                    }

                    const errorMessage = error.error?.message || 'Unauthorized access';
                    return throwError(() => new Error(errorMessage));
                }

                if (error.status === 404) {
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
                const errorMessage = error.error?.message || error.statusText || 'Something went wrong';
                return throwError(() => new Error(errorMessage));
            })
        );
    }
}
