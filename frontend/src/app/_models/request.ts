import { Employee } from './employee';
import { RequestItem } from './request-item';

export class Request {
    id?: number;
    employeeId?: number;
    status?: 'Pending' | 'Approved' | 'Rejected';
    type?: string;
    created?: Date;
    updated?: Date;
    
    // Navigation properties
    employee?: Employee;
    items?: RequestItem[];
    
    // UI properties
    isDeleting?: boolean;
    updating?: boolean;
} 