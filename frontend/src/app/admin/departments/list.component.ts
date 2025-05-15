import { Component, OnInit } from '@angular/core';
import { first } from 'rxjs/operators';

import { DepartmentService } from '@app/_services';
import { Department } from '@app/_models/department';

@Component({ templateUrl: 'list.component.html' })
export class ListComponent implements OnInit {
    departments: Department[] = [];
    pagedDepartments: Department[] = [];
    loading = false;
    
    // Pagination
    currentPage = 0;
    pageSize = 5;
    totalPages = 0;
    
    constructor(private departmentService: DepartmentService) {}
    
    ngOnInit() {
        this.loadDepartments();
    }
    
    loadDepartments() {
        this.loading = true;
        this.departmentService.getAll()
            .pipe(first())
            .subscribe({
                next: departments => {
                    this.departments = departments;
                    this.totalPages = Math.ceil(this.departments.length / this.pageSize);
                    this.setPage(0);
                    this.loading = false;
                },
                error: error => {
                    console.error('Error loading departments:', error);
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
        const end = Math.min(start + this.pageSize, this.departments.length);
        this.pagedDepartments = this.departments.slice(start, end);
    }
    
    deleteDepartment(id: number) {
        const department = this.departments.find(x => x.id === id);
        if (!department) return;
        
        department.isDeleting = true;
        this.departmentService.delete(id)
            .pipe(first())
            .subscribe({
                next: () => {
                    this.departments = this.departments.filter(x => x.id !== id);
                    this.totalPages = Math.ceil(this.departments.length / this.pageSize);
                    
                    // If current page is now empty and not the first page, go to previous page
                    if (this.currentPage > 0 && this.currentPage >= this.totalPages) {
                        this.setPage(this.currentPage - 1);
                    } else {
                        this.setPage(this.currentPage);
                    }
                },
                error: error => {
                    console.error('Error deleting department:', error);
                    department.isDeleting = false;
                }
            });
    }
} 