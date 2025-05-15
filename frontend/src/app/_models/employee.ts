import { Department } from './department';

export class Employee {
    id?: number;
    firstName?: string;
    lastName?: string;
    email?: string;
    departmentId?: number;
    position?: string;
    hireDate?: Date;
    phone?: string;
    status?: 'Active' | 'Inactive';
    created?: Date;
    updated?: Date;
    
    // Navigation properties
    department?: Department;
    
    // UI properties
    isDeleting?: boolean;
} 