import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, of, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { environment } from '../../environments/environment';
import { Employee } from '../_models/employee';

const baseUrl = environment.apiUrl.replace('/accounts', '');

@Injectable({ providedIn: 'root' })
export class EmployeeService {
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

    getAll(): Observable<Employee[]> {
        return this.http.get<Employee[]>(`${baseUrl}/employees`, this.getHttpOptions())
            .pipe(catchError(error => {
                console.error('Error fetching employees:', error);
                return of([]);
            }));
    }

    getById(id: number): Observable<Employee> {
        return this.http.get<Employee>(`${baseUrl}/employees/${id}`, this.getHttpOptions());
    }

    getUsers(): Observable<any[]> {
        return this.http.get<any[]>(`${baseUrl}/employees/users`, this.getHttpOptions())
            .pipe(catchError(error => {
                console.error('Error fetching users for employees:', error);
                return of([]);
            }));
    }

    create(employee: Employee): Observable<Employee> {
        return this.http.post<Employee>(`${baseUrl}/employees`, employee, this.getHttpOptions())
            .pipe(catchError(error => {
                // Get the detailed error message if available
                const errorMessage = error.error?.message || error.message || 'Failed to create employee';
                console.error('Error creating employee:', errorMessage);
                return throwError(() => new Error(errorMessage));
            }));
    }

    update(id: number, employee: Employee): Observable<Employee> {
        return this.http.put<Employee>(`${baseUrl}/employees/${id}`, employee, this.getHttpOptions());
    }

    delete(id: number): Observable<any> {
        return this.http.delete<any>(`${baseUrl}/employees/${id}`, this.getHttpOptions());
    }

    transfer(id: number, departmentId: number): Observable<any> {
        return this.http.post<any>(`${baseUrl}/employees/${id}/transfer`, { departmentId }, this.getHttpOptions());
    }
} 