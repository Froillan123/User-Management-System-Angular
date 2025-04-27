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
                if ([401, 403].includes(error.status)) {
                    // If the error is due to authentication/authorization
                    if (error.status === 401 && !request.url.includes('authenticate')) {
                        // Auto logout if 401 response returned from api and not a login request
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
