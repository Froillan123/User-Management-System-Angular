import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, of } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { environment } from '../../environments/environment';
import { Department } from '../_models/department';

const baseUrl = environment.apiUrl.replace('/accounts', '');

@Injectable({ providedIn: 'root' })
export class DepartmentService {
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

    getAll(): Observable<Department[]> {
        return this.http.get<Department[]>(`${baseUrl}/departments`, this.getHttpOptions())
            .pipe(catchError(error => {
                console.error('Error fetching departments:', error);
                return of([]);
            }));
    }

    getById(id: number): Observable<Department> {
        return this.http.get<Department>(`${baseUrl}/departments/${id}`, this.getHttpOptions());
    }

    create(department: Department): Observable<Department> {
        return this.http.post<Department>(`${baseUrl}/departments`, department, this.getHttpOptions());
    }

    update(id: number, department: Department): Observable<Department> {
        return this.http.put<Department>(`${baseUrl}/departments/${id}`, department, this.getHttpOptions());
    }

    delete(id: number): Observable<any> {
        return this.http.delete<any>(`${baseUrl}/departments/${id}`, this.getHttpOptions());
    }
} 