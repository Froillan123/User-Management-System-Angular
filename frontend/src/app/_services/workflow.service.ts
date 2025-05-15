import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, of, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { environment } from '../../environments/environment';
import { Workflow } from '../_models/workflow';
import { map } from 'rxjs/operators';

const baseUrl = environment.apiUrl.replace('/accounts', '');

@Injectable({ providedIn: 'root' })
export class WorkflowService {
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

    getAll(): Observable<Workflow[]> {
        return this.http.get<Workflow[]>(`${baseUrl}/workflows`, this.getHttpOptions())
            .pipe(catchError(error => {
                console.error('Error fetching workflows:', error);
                return of([]);
            }));
    }

    getById(id: number): Observable<Workflow> {
        return this.http.get<Workflow>(`${baseUrl}/workflows/${id}`, this.getHttpOptions());
    }
    
    getByEmployeeId(employeeId: number): Observable<Workflow[]> {
        return this.http.get<Workflow[]>(`${baseUrl}/workflows/employee/${employeeId}`, this.getHttpOptions())
            .pipe(catchError(error => {
                console.error(`Error fetching workflows for employee ${employeeId}:`, error);
                return of([]);
            }));
    }
    
    create(workflow: any): Observable<Workflow> {
        return this.http.post<Workflow>(`${baseUrl}/workflows`, workflow, this.getHttpOptions())
            .pipe(catchError(error => {
                console.error('Error creating workflow:', error);
                return throwError(() => new Error(error.message || 'Failed to create workflow'));
            }));
    }
    
    updateStatus(id: number, status: string): Observable<Workflow> {
        return this.http.put<Workflow>(`${baseUrl}/workflows/${id}/status`, { status }, this.getHttpOptions());
    }
    
    update(id: number, workflow: any): Observable<Workflow> {
        return this.http.put<Workflow>(`${baseUrl}/workflows/${id}`, workflow, this.getHttpOptions())
            .pipe(catchError(error => {
                console.error('Error updating workflow:', error);
                return throwError(() => new Error(error.message || 'Failed to update workflow'));
            }));
    }
    
    findByRequestId(employeeId: number, requestId: number): Observable<Workflow[]> {
        return this.getByEmployeeId(employeeId).pipe(
            map(workflows => workflows.filter(w => w.details?.requestId === requestId))
        );
    }
    
    delete(id: number): Observable<any> {
        return this.http.delete(`${baseUrl}/workflows/${id}`, this.getHttpOptions())
            .pipe(catchError(error => {
                console.error('Error deleting workflow:', error);
                return throwError(() => new Error(error.message || 'Failed to delete workflow'));
            }));
    }
}