import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, of } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { environment } from '../../environments/environment';
import { Request } from '../_models/request';

const baseUrl = environment.apiUrl.replace('/accounts', '');

@Injectable({ providedIn: 'root' })
export class RequestService {
    constructor(private http: HttpClient) { }

    private getHttpOptions() {
        const accountJson = localStorage.getItem('account');
        if (!accountJson) return {};
        
        try {
            const account = JSON.parse(accountJson);
            return {
                headers: new HttpHeaders({
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${account.jwtToken}`
                })
            };
        } catch (error) {
            console.error('Error parsing account from localStorage', error);
            return {};
        }
    }

    getAll(): Observable<Request[]> {
        return this.http.get<Request[]>(`${baseUrl}/requests`, this.getHttpOptions())
            .pipe(catchError(error => {
                console.error('Error fetching requests:', error);
                return of([]);
            }));
    }

    getById(id: number): Observable<Request> {
        return this.http.get<Request>(`${baseUrl}/requests/${id}`, this.getHttpOptions());
    }

    getByEmployeeId(employeeId: number): Observable<Request[]> {
        return this.http.get<Request[]>(`${baseUrl}/requests/employee/${employeeId}`, this.getHttpOptions())
            .pipe(catchError(error => {
                console.error(`Error fetching requests for employee ${employeeId}:`, error);
                return of([]);
            }));
    }

    create(request: Request): Observable<Request> {
        return this.http.post<Request>(`${baseUrl}/requests`, request, this.getHttpOptions());
    }

    update(id: number, request: Request): Observable<Request> {
        return this.http.put<Request>(`${baseUrl}/requests/${id}`, request, this.getHttpOptions());
    }

    delete(id: number): Observable<any> {
        return this.http.delete<any>(`${baseUrl}/requests/${id}`, this.getHttpOptions());
    }

    updateStatus(id: number, status: string): Observable<Request> {
        return this.http.put<Request>(`${baseUrl}/requests/${id}/status`, { status }, this.getHttpOptions());
    }
} 