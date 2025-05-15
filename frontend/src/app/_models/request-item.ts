export class RequestItem {
    id?: number;
    requestId?: number;
    name?: string;
    quantity?: number;
    status?: 'Pending' | 'Approved' | 'Rejected';
} 