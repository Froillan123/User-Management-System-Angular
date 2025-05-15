import { Employee } from './employee';

export class Workflow {
    id?: number;
    employeeId?: number;
    type?: string;
    details?: any;
    status?: string;
    created?: Date;
    
    // Navigation properties
    employee?: Employee;
    
    // UI properties
    updating?: boolean;
} 