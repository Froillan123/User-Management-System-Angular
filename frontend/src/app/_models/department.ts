export class Department {
    id?: number;
    name?: string;
    description?: string;
    managerId?: number;
    created?: Date;
    updated?: Date;
    
    // Additional properties 
    employeeCount?: number;
    
    // UI properties
    isDeleting?: boolean;
} 