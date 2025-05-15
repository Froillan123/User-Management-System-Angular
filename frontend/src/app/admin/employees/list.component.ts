import { Component, OnInit } from '@angular/core';
import { first } from 'rxjs/operators';

import { EmployeeService } from '../../_services/employee.service';
import { AlertService } from '../../_services/alert.service';
import { Employee } from '../../_models/employee';

@Component({ templateUrl: 'list.component.html' })
export class ListComponent implements OnInit {
    employees: Employee[] = [];
    pagedEmployees: Employee[] = [];
    loading = false;
    
    // Pagination
    currentPage = 0;
    pageSize = 5;
    totalPages = 0;
    
    constructor(
        private employeeService: EmployeeService,
        private alertService: AlertService
    ) {}
    
    ngOnInit() {
        this.loadEmployees();
    }
    
    loadEmployees() {
        this.loading = true;
        this.employeeService.getAll()
            .pipe(first())
            .subscribe({
                next: employees => {
                    this.employees = employees;
                    this.totalPages = Math.ceil(this.employees.length / this.pageSize);
                    this.setPage(0);
                    this.loading = false;
                },
                error: error => {
                    this.alertService.error(error);
                    this.loading = false;
                }
            });
    }
    
    setPage(page: number) {
        if (page < 0 || page >= this.totalPages) {
            return;
        }
        
        this.currentPage = page;
        const start = this.currentPage * this.pageSize;
        const end = Math.min(start + this.pageSize, this.employees.length);
        this.pagedEmployees = this.employees.slice(start, end);
    }
    
    deleteEmployee(id: number) {
        const employee = this.employees.find(x => x.id === id);
        if (!employee) return;
        
        employee.isDeleting = true;
        this.employeeService.delete(id)
            .pipe(first())
            .subscribe({
                next: () => {
                    this.employees = this.employees.filter(x => x.id !== id);
                    this.totalPages = Math.ceil(this.employees.length / this.pageSize);
                    
                    // If current page is now empty and not the first page, go to previous page
                    if (this.currentPage > 0 && this.currentPage >= this.totalPages) {
                        this.setPage(this.currentPage - 1);
                    } else {
                        this.setPage(this.currentPage);
                    }
                    
                    this.alertService.success('Employee deleted successfully');
                },
                error: error => {
                    this.alertService.error(error);
                    employee.isDeleting = false;
                }
            });
    }
} 