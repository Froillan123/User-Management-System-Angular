import { Injectable } from '@angular/core';
import { HttpRequest, HttpResponse, HttpHandler, HttpEvent, HttpInterceptor, HTTP_INTERCEPTORS, HttpHeaders } from '@angular/common/http';
import { Observable, of, throwError } from 'rxjs';
import { delay, materialize, dematerialize } from 'rxjs/operators';

import { AlertService } from '../../app/_services';
import { Role } from '../../app/_models';

// Local storage keys
const accountsKey = 'angular-10-signup-verification-boilerplate-accounts';
const employeesKey = 'angular-10-employees';
const departmentsKey = 'angular-10-departments';
const requestsKey = 'angular-10-requests';
const workflowsKey = 'angular-10-workflows';

// Initialize data only if it doesn't exist in localStorage
let accounts = JSON.parse(localStorage.getItem(accountsKey) || '[]');
let employees = JSON.parse(localStorage.getItem(employeesKey) || '[]');
let departments = JSON.parse(localStorage.getItem(departmentsKey) || '[]');
let requests = JSON.parse(localStorage.getItem(requestsKey) || '[]');
let workflows = JSON.parse(localStorage.getItem(workflowsKey) || '[]');

// If departments are empty, initialize with default departments
if (departments.length === 0) {
    departments = [
        { id: 1, name: 'Human Resources', description: 'HR Department', createdAt: new Date().toISOString() },
        { id: 2, name: 'Information Technology', description: 'IT Department', createdAt: new Date().toISOString() },
        { id: 3, name: 'Finance', description: 'Finance Department', createdAt: new Date().toISOString() },
        { id: 4, name: 'Marketing', description: 'Marketing Department', createdAt: new Date().toISOString() }
    ];
    localStorage.setItem(departmentsKey, JSON.stringify(departments));
}

@Injectable()
export class FakeBackendInterceptor implements HttpInterceptor {
    constructor(private alertService: AlertService) { }

    intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
        const { url, method, headers, body } = request;
        const alertService = this.alertService;

        return handleRoute();

        function handleRoute() {
            switch (true) {
                // Account routes
                case url.endsWith('/accounts/authenticate') && method === 'POST':
                    return authenticate();
                case url.endsWith('/accounts/refresh-token') && method === 'POST':
                    return refreshToken();
                case url.endsWith('/accounts/revoke-token') && method === 'POST':
                    return revokeToken();
                case url.endsWith('/accounts/register') && method === 'POST':
                    return register();
                case url.endsWith('/accounts/verify-email') && method === 'POST':
                    return verifyEmail();
                case url.endsWith('/accounts/forgot-password') && method === 'POST':
                    return forgotPassword();
                case url.endsWith('/accounts/validate-reset-token') && method === 'POST':
                    return validateResetToken();
                case url.endsWith('/accounts/reset-password') && method === 'POST':
                    return resetPassword();
                case url.endsWith('/accounts') && method === 'GET':
                    return getAccounts();
                case url.endsWith('/accounts/unlinked') && method === 'GET':
                    return getUnlinkedAccounts();
                case url.match(/\/accounts\/\d+$/) && method === 'GET':
                    return getAccountById();
                case url.endsWith('/accounts') && method === 'POST':
                    return createAccount();
                case url.match(/\/accounts\/\d+$/) && method === 'PUT':
                    return updateAccount();
                case url.match(/\/accounts\/\d+$/) && method === 'DELETE':
                    return deleteAccount();
                case url.endsWith('/analytics/user-stats') && method === 'GET':
                    return getUserStats();
                case url.endsWith('/analytics/online-users') && method === 'GET':
                    return getOnlineUsers();
                
                // Employee routes
                case url.endsWith('/employees') && method === 'GET':
                    return getEmployees();
                case url.match(/\/employees\/\d+$/) && method === 'GET':
                    return getEmployeeById();
                case url.endsWith('/employees') && method === 'POST':
                    return createEmployee();
                case url.match(/\/employees\/\d+$/) && method === 'PUT':
                    return updateEmployee();
                case url.match(/\/employees\/\d+$/) && method === 'DELETE':
                    return deleteEmployee();
                case url.endsWith('/employees/users') && method === 'GET':
                    return getUsers();
                case url.match(/\/employees\/\d+\/transfer$/) && method === 'POST':
                    return transferEmployee();
                
                // Department routes
                case url.endsWith('/departments') && method === 'GET':
                    return getDepartments();
                case url.match(/\/departments\/\d+$/) && method === 'GET':
                    return getDepartmentById();
                case url.endsWith('/departments') && method === 'POST':
                    return createDepartment();
                case url.match(/\/departments\/\d+$/) && method === 'PUT':
                    return updateDepartment();
                case url.match(/\/departments\/\d+$/) && method === 'DELETE':
                    return deleteDepartment();
                
                // Request routes
                case url.endsWith('/requests') && method === 'GET':
                    return getRequests();
                case url.match(/\/requests\/\d+$/) && method === 'GET':
                    return getRequestById();
                case url.endsWith('/requests') && method === 'POST':
                    return createRequest();
                case url.match(/\/requests\/\d+$/) && method === 'PUT':
                    return updateRequest();
                case url.match(/\/requests\/\d+\/status$/) && method === 'PUT':
                    return updateRequestStatus();
                case url.match(/\/requests\/\d+$/) && method === 'DELETE':
                    return deleteRequest();
                
                // Workflow routes
                case url.endsWith('/workflows') && method === 'GET':
                    return getWorkflows();
                case url.match(/\/workflows\/employee\/\d+$/) && method === 'GET':
                    return getWorkflowsByEmployeeId();
                case url.match(/\/workflows\/\d+$/) && method === 'GET':
                    return getWorkflowById();
                case url.endsWith('/workflows') && method === 'POST':
                    return createWorkflow();
                case url.match(/\/workflows\/\d+\/status$/) && method === 'PUT':
                    return updateWorkflowStatus();
                case url.match(/\/workflows\/\d+$/) && method === 'DELETE':
                    return deleteWorkflow();
                
                default:
                    return next.handle(request);
            }
        }

        // Analytics functions
        function getUserStats() {
            if (!isAuthorized(Role.Admin)) return unauthorized();
            
            // Get monthly registration data (simulated)
            const monthlyData = generateMonthlyData();
            
            // Get user statistics
            const totalUsers = accounts.length;
            const activeUsers = accounts.filter(x => x.status === 'Active').length;
            const verifiedUsers = accounts.filter(x => x.isVerified).length;
            const onlineUsers = accounts.filter(x => x.isOnline).length;
            const refreshTokenCount = accounts.reduce((count, account) => 
                count + (account.refreshTokens ? account.refreshTokens.length : 0), 0);
            
            return ok({
                totalUsers,
                activeUsers,
                verifiedUsers,
                onlineUsers,
                refreshTokenCount,
                monthlyData
            });
        }

        function getOnlineUsers() {
            if (!isAuthorized(Role.Admin)) return unauthorized();
            
            // Update random online statuses for simulation
            updateOnlineStatuses();
            
            // Return all users with their online status
            return ok(accounts.map(x => ({
                ...basicDetails(x),
                isOnline: x.isOnline,
                lastActive: x.lastActive
            })));
        }

        function updateOnlineStatuses() {
            // Update online status based on last active time
            const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
            
            accounts = accounts.map(account => {
                const lastActive = account.lastActive ? new Date(account.lastActive) : null;
                account.isOnline = lastActive && lastActive > fiveMinutesAgo;
                return account;
            });
            
            localStorage.setItem(accountsKey, JSON.stringify(accounts));
        }

        function generateMonthlyData() {
            // Get all months in the current year
            const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
            const currentMonth = new Date().getMonth();
            
            // Initialize monthly counts
            const monthlyCounts = months.map(month => ({
                month,
                count: 0,
                isCurrent: false
            }));
            
            // Count registrations by month
            accounts.forEach(account => {
                if (account.dateCreated) {
                    const createdDate = new Date(account.dateCreated);
                    const monthIndex = createdDate.getMonth();
                    monthlyCounts[monthIndex].count++;
                }
            });
            
            // Mark current month
            monthlyCounts[currentMonth].isCurrent = true;
            
            return monthlyCounts;
        }

        // role functions

        function authenticate() {
            const { email, password } = body;
            const account = accounts.find(x => x.email === email);

            if (!account) return error('Email does not exist');
            if (!account.isVerified) {
                setTimeout(() => {
                    const verifyUrl = `${location.origin}/account/verify-email?token=${account.verificationToken}`;
                    alertService.info(
                        `<h4>Account Not Verified</h4>
                        <p>Please verify your email address to continue:</p>
                        <p><a href="${verifyUrl}">${verifyUrl}</a></p>`,
                        { autoClose: false }
                    );
                }, 1000);
                return error('Account not verified');
            }
            if (account.status === 'Inactive') {
                return error('Your account is inactive. Please contact an administrator to activate your account.');
            }
            if (account.password !== password) return error('Password is incorrect');

            // Set account to online
            account.isOnline = true;
            account.lastActive = new Date().toISOString();

            // add refresh token to account
            if (!account.refreshTokens) account.refreshTokens = [];
            account.refreshTokens.push(generateRefreshToken());
            localStorage.setItem(accountsKey, JSON.stringify(accounts));

            // create and return jwt token
            const jwtToken = generateJwtToken(account);
            return ok({
                ...basicDetails(account),
                jwtToken
            });
        }

        function refreshToken() {
            const refreshToken = getRefreshToken();

            if (!refreshToken) return unauthorized();

            const account = accounts.find(x => x.refreshTokens && x.refreshTokens.includes(refreshToken));

            if (!account) return unauthorized();

            // Update active status
            account.lastActive = new Date().toISOString();
            account.isOnline = true;

            // replace old refresh token with new one and save
            account.refreshTokens = account.refreshTokens.filter(x => x !== refreshToken);
            account.refreshTokens.push(generateRefreshToken());
            localStorage.setItem(accountsKey, JSON.stringify(accounts));

            return ok({
                ...basicDetails(account),
                jwtToken: generateJwtToken(account)
            });
        }

        function revokeToken() {
            if (!isAuthenticated()) return unauthorized();

            const refreshToken = getRefreshToken();
            const account = accounts.find(x => x.refreshTokens && x.refreshTokens.includes(refreshToken));

            if (!account) return unauthorized();

            // Set account to offline when token is revoked (logout)
            account.isOnline = false;
            account.lastActive = new Date().toISOString();

            account.refreshTokens = account.refreshTokens.filter(x => x !== refreshToken);
            localStorage.setItem(accountsKey, JSON.stringify(accounts));

            return ok();
        }

        function register() {
            const account = body;
            account.refreshTokens = [];
            account.dateCreated = new Date().toISOString();
            account.lastActive = new Date().toISOString();
            account.isOnline = false;
            account.acceptTerms = true;
            
            if (accounts.length === 0) {
                // First user is Admin
                account.role = Role.Admin;
                account.isVerified = true;
                account.status = 'Active';
                account.id = 1;
                accounts.push(account);
                localStorage.setItem(accountsKey, JSON.stringify(accounts));
                
                // Create employee record for admin with proper account linking
                const employee = {
                    id: 1,
                    employeeId: 'EMP001',  // Format: EMP001
                    firstName: account.firstName,
                    lastName: account.lastName,
                    email: account.email,
                    position: 'Manager',
                    departmentId: 2, // IT Department
                    phoneNumber: `+1 555-${Math.floor(1000 + Math.random() * 9000)}`,
                    hireDate: account.dateCreated,
                    address: '123 Main St, City, Country',
                    salary: 90000,
                    status: 'Active',
                    accountId: account.id,
                    createdAt: account.dateCreated,
                    updatedAt: account.dateCreated
                };
                employees.push(employee);
                localStorage.setItem(employeesKey, JSON.stringify(employees));
                
                // Create onboarding workflow for admin
                const workflow = {
                    id: 1,
                    employeeId: employee.id,
                    type: 'Onboarding',
                    status: 'Completed',
                    details: {
                        departmentId: employee.departmentId,
                        departmentName: 'Information Technology',
                        message: 'Added to Information Technology'
                    },
                    created: account.dateCreated,
                    updated: account.dateCreated
                };
                workflows.push(workflow);
                localStorage.setItem(workflowsKey, JSON.stringify(workflows));
                
                setTimeout(() => {
                    alertService.success('Registration successful! You can now log in.', { autoClose: true });
                }, 1000);
                
                return ok({
                    message: 'Registration successful. You can now login.'
                });
            } else {
                // Regular users
                account.role = Role.User;
                account.isVerified = false;
                account.status = 'Inactive';
                account.id = newAccountId();
                account.verificationToken = new Date().getTime().toString();
                accounts.push(account);
                localStorage.setItem(accountsKey, JSON.stringify(accounts));

                // Do NOT create an employee record automatically - this will be done when an admin adds an employee

                setTimeout(() => {
                    const verifyUrl = `${location.origin}/account/verify-email?token=${account.verificationToken}`;
                    alertService.info(
                        `<h4>Verification Email</h4>
                        <p>Thanks for registering!</p>
                        <p>Please click the below link to verify your email address:</p>
                        <p><a href="${verifyUrl}">${verifyUrl}</a></p>
                        <p>After verification, please wait for an administrator to activate your account before you can log in.</p>
                        <div><strong>NOTE:</strong> The fake backend displayed this "email" so you can test without an api. A real backend would send a real email.</div>`,
                        { autoClose: false }
                    );
                }, 1000);
                
                return ok({
                    message: 'Registration successful, please check your email for verification instructions'
                });
            }
        }

        function verifyEmail() {
            const { token } = body;
            
            // Ensure accounts are loaded from localStorage
            accounts = JSON.parse(localStorage.getItem(accountsKey) || '[]');
            
            const account = accounts.find(x => !!x.verificationToken && x.verificationToken === token);

            if (!account) return error('Verification failed: Invalid token');

            // Automatically verify the account and set to active
            account.isVerified = true;
            account.status = 'Active';
            account.verificationToken = undefined; // Clear token after verification
            localStorage.setItem(accountsKey, JSON.stringify(accounts));

            // Show success message
            setTimeout(() => {
                alertService.success('Email verified successfully! Your account is now active and you can log in.', { autoClose: true });
            }, 500);

            return ok();
        }

        function forgotPassword() {
            const { email } = body;
            const account = accounts.find(x => x.email === email);

            if (!account) return ok();

            account.resetToken = new Date().getTime().toString();
            account.resetTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
            localStorage.setItem(accountsKey, JSON.stringify(accounts));

            setTimeout(() => {
                const resetUrl = `${location.origin}/account/reset-password?token=${account.resetToken}`;
                alertService.info(
                    `<h4>Reset Password Email</h4>
                <p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
                <p><a href="${resetUrl}">${resetUrl}</a></p>
                <div><strong>NOTE:</strong> The fake backend displayed this "email" so you can test without an api. A real backend would send a real email.</div>`,
                    { autoClose: false }
                );
            }, 1000);

            return ok();
        }

        function validateResetToken() {
            const { token } = body;
            const account = accounts.find(x =>
                !!x.resetToken &&
                x.resetToken === token &&
                new Date() < new Date(x.resetTokenExpires)
            );

            if (!account) return error('Invalid token');

            return ok();
        }

        function resetPassword() {
            const { token, password } = body;
            const account = accounts.find(x =>
                !!x.resetToken &&
                x.resetToken === token &&
                new Date() < new Date(x.resetTokenExpires)
            );

            if (!account) return error('Invalid token');

            account.password = password;
            account.resetToken = null;
            account.resetTokenExpires = null;
            localStorage.setItem(accountsKey, JSON.stringify(accounts));

            return ok();
        }

        function getAccounts() {
            if (!isAuthenticated()) return unauthorized();

            // Ensure all accounts have valid IDs
            accounts = accounts.map(acc => {
                if (!acc.refreshTokens) acc.refreshTokens = [];
                
                // Ensure account has a valid ID
                if (!acc.id || isNaN(acc.id)) {
                    acc.id = newAccountId();
                }
                return acc;
            });
            localStorage.setItem(accountsKey, JSON.stringify(accounts));
            
            return ok(accounts.map(x => basicDetails(x)));
        }

        function getAccountById() {
            if (!isAuthenticated()) return unauthorized();

            let account = accounts.find(x => x.id === idFromUrl());
            
            if (!account) return notFound();
            
            if (account.id !== currentAccount().id && !isAuthorized(Role.Admin)) {
                return unauthorized();
            }

            return ok(basicDetails(account));
        }

        function createAccount() {
            if (!isAuthorized(Role.Admin)) return unauthorized();

            const account = body;
            account.refreshTokens = [];
            
            if (accounts.find(x => x.email === account.email)) {
                return error(`Email ${account.email} is already registered`);
            }

            // Ensure acceptTerms is true when admin creates an account
            account.acceptTerms = true;
            account.id = newAccountId();
            account.dateCreated = new Date().toISOString();
            account.lastActive = new Date().toISOString();
            account.isOnline = false;
            // Force all created accounts to be regular users
            account.role = Role.User;
            account.isVerified = true;
            account.status = 'Active';
            delete account.confirmPassword;
            accounts.push(account);
            localStorage.setItem(accountsKey, JSON.stringify(accounts));

            // Show success message for admin-created accounts
            setTimeout(() => {
                alertService.success('Account created successfully! The account is verified and active.', { autoClose: true });
            }, 1000);

            return ok();
        }

        function updateAccount() {
            if (!isAuthenticated()) return unauthorized();

            const params = body;
            let account = accounts.find(x => x.id === idFromUrl());
            
            if (!account) return notFound();

            if (account.id !== currentAccount().id && !isAuthorized(Role.Admin)) {
                return unauthorized();
            }

            // Only update password if it's provided and not empty
            if (params.password) {
                account.password = params.password;
            }

            // Remove password and confirmPassword from params to avoid overwriting
            delete params.password;
            delete params.confirmPassword;

            // Update other fields
            Object.assign(account, params);
            localStorage.setItem(accountsKey, JSON.stringify(accounts));

            return ok(basicDetails(account));
        }

        function deleteAccount() {
            if (!isAuthenticated()) return unauthorized();

            let account = accounts.find(x => x.id === idFromUrl());
            
            if (!account) return notFound();

            if (account.id !== currentAccount().id && !isAuthorized(Role.Admin)) {
                return unauthorized();
            }

            accounts = accounts.filter(x => x.id !== idFromUrl());
            localStorage.setItem(accountsKey, JSON.stringify(accounts));
            return ok();
        }

        // Employee functions
        function getEmployees() {
            if (!isAuthenticated()) return unauthorized();
            
            // Get query parameters if any
            const queryString = url.split('?')[1] || '';
            const params = new URLSearchParams(queryString);
            
            // Parse and handle query parameters safely
            const departmentIdParam = params.get('departmentId');
            const departmentId = departmentIdParam ? parseInt(departmentIdParam) : null;
            const status = params.get('status') || '';
            const searchTerm = params.get('search') || '';
            
            // First filter employees based on query parameters
            let filteredEmployees = [...employees];
            
            if (departmentId) {
                filteredEmployees = filteredEmployees.filter(e => e.departmentId === departmentId);
            }
            
            if (status) {
                filteredEmployees = filteredEmployees.filter(e => e.status === status);
            }
            
            if (searchTerm) {
                const search = searchTerm.toLowerCase();
                filteredEmployees = filteredEmployees.filter(e => 
                    (e.firstName && e.firstName.toLowerCase().includes(search)) || 
                    (e.lastName && e.lastName.toLowerCase().includes(search)) || 
                    (e.email && e.email.toLowerCase().includes(search)) ||
                    (e.position && e.position.toLowerCase().includes(search))
                );
            }
            
            // Add department details to employees
            const employeesWithDepartments = filteredEmployees.map(employee => {
                const department = departments.find(d => d.id === employee.departmentId);
                
                // Ensure accountId is a number
                const accountId = typeof employee.accountId === 'string' ? 
                    parseInt(employee.accountId) : employee.accountId;
                
                // Find linked account - use full object for debugging
                const linkedAccount = accountId ? accounts.find(a => a.id === accountId) : null;
                
                return {
                    ...employee,
                    accountId: accountId,
                    department: department ? {
                        id: department.id,
                        name: department.name,
                        description: department.description
                    } : null,
                    account: linkedAccount ? {
                        id: linkedAccount.id,
                        email: linkedAccount.email,
                        name: `${linkedAccount.firstName} ${linkedAccount.lastName}`
                    } : null
                };
            });
            
            return ok(employeesWithDepartments);
        }

        function getEmployeeById() {
            if (!isAuthenticated()) return unauthorized();
            
            const employee = employees.find(x => x.id === idFromUrl());
            return employee ? ok(employee) : notFound();
        }

        function createEmployee() {
            if (!isAuthorized(Role.Admin)) return unauthorized();
            
            const employee = body;
            
            // Get current employees and departments from localStorage
            const storedEmployees = JSON.parse(localStorage.getItem(employeesKey) || '[]');
            const storedDepartments = JSON.parse(localStorage.getItem(departmentsKey) || '[]');
            const storedAccounts = JSON.parse(localStorage.getItem(accountsKey) || '[]');
            const storedWorkflows = JSON.parse(localStorage.getItem(workflowsKey) || '[]');
            
            // Check if account is already linked to another employee
            if (employee.accountId) {
                const accountId = typeof employee.accountId === 'string' 
                    ? parseInt(employee.accountId) 
                    : employee.accountId;
                
                if (storedEmployees.some(e => e.accountId === accountId)) {
                return error(`This account is already linked to an employee record`);
            }
            
                // Ensure account exists
                const account = storedAccounts.find(a => a.id === accountId);
                if (!account) {
                    return error(`Account with ID ${accountId} does not exist`);
                }
                
                // Apply account details if not provided
                if (!employee.firstName) employee.firstName = account.firstName;
                if (!employee.lastName) employee.lastName = account.lastName;
                if (!employee.email) employee.email = account.email;
                
                // Ensure accountId is stored as integer
                employee.accountId = accountId;
            }
            
            // Check if employee with same email already exists
            if (employee.email && storedEmployees.find(x => x.email === employee.email)) {
                return error(`Employee with email ${employee.email} already exists`);
            }
            
            // Validate departmentId
            if (employee.departmentId) {
                // Convert to integer if it's a string
                const departmentId = typeof employee.departmentId === 'string' 
                    ? parseInt(employee.departmentId) 
                    : employee.departmentId;
                
                // Check if department exists
                if (!storedDepartments.some(d => d.id === departmentId)) {
                    return error(`Department with ID ${departmentId} does not exist`);
                }
                
                employee.departmentId = departmentId;
            }
            
            // Generate new employee ID
            const newId = storedEmployees.length ? Math.max(...storedEmployees.map(x => x.id)) + 1 : 1;
            const employeeIdNumber = String(newId).padStart(3, '0');
            
            // Complete the employee object
            const newEmployee = {
                ...employee,
                id: newId,
                employeeId: `EMP${employeeIdNumber}`,
                status: employee.status || 'Active',
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString()
            };
            
            // Add the new employee to both local variable and localStorage
            storedEmployees.push(newEmployee);
            employees.push(newEmployee); // Add to the in-memory array too
            localStorage.setItem(employeesKey, JSON.stringify(storedEmployees));
            
            // Create onboarding workflow - only create one workflow
            if (newEmployee.departmentId) {
                const department = storedDepartments.find(d => d.id === newEmployee.departmentId);
                const workflowId = storedWorkflows.length ? Math.max(...storedWorkflows.map(x => x.id)) + 1 : 1;
                
                const workflow = {
                    id: workflowId,
                    employeeId: newEmployee.id, // Use integer ID
                    type: 'Onboarding',
                    status: 'Completed',
                    details: {
                        departmentId: newEmployee.departmentId,
                        departmentName: department ? department.name : 'Unknown Department',
                        message: `Added to ${department ? department.name : 'Unknown Department'}`
                    },
                    created: new Date().toISOString(),
                    updated: new Date().toISOString()
                };
                
                storedWorkflows.push(workflow);
                workflows.push(workflow); // Add to the in-memory array too
                localStorage.setItem(workflowsKey, JSON.stringify(storedWorkflows));
            }
            
            return ok(newEmployee);
        }

        function updateEmployee() {
            if (!isAuthenticated()) return unauthorized();
            
            const id = idFromUrl();
            if (id === null) return notFound();
            
            const employeeIndex = employees.findIndex(x => x.id === id);
            
            if (employeeIndex === -1) return notFound();
            
            // Check if updating to an email that already exists with different ID
            if (body.email && employees.some(x => x.email === body.email && x.id !== id)) {
                return error(`Employee with email ${body.email} already exists`);
            }
            
            // Check if this is a department transfer
            const oldDepartmentId = employees[employeeIndex].departmentId;
            const newDepartmentId = body.departmentId ? 
                (typeof body.departmentId === 'string' ? parseInt(body.departmentId) : body.departmentId) : 
                oldDepartmentId;
            
            // If departmentId is changing and it's not explicitly a transfer workflow, create a workflow
            if (newDepartmentId !== oldDepartmentId && !body._skipWorkflow) {
                // Check if department exists
                const departmentExists = departments.some(d => d.id === newDepartmentId);
                if (!departmentExists) {
                    return error(`Department with ID ${newDepartmentId} does not exist`);
                }
                
                const oldDepartment = departments.find(d => d.id === oldDepartmentId);
                const newDepartment = departments.find(d => d.id === newDepartmentId);
                
                // Create a transfer workflow if not already created
                const transferWorkflow = {
                    id: workflows.length ? Math.max(...workflows.map(x => x.id)) + 1 : 1,
                    employeeId: id,
                    type: 'Transfer',
                    status: 'Pending',
                    details: {
                        oldDepartmentId: oldDepartmentId,
                        departmentId: newDepartmentId,
                        oldDepartmentName: oldDepartment ? oldDepartment.name : 'None',
                        newDepartmentName: newDepartment ? newDepartment.name : 'Unknown Department',
                        message: `Transfer from ${oldDepartment ? oldDepartment.name : 'None'} to ${newDepartment ? newDepartment.name : 'Unknown Department'}`
                    },
                    created: new Date().toISOString(),
                    updated: new Date().toISOString()
                };
                workflows.push(transferWorkflow);
                localStorage.setItem(workflowsKey, JSON.stringify(workflows));
                
                // Don't update the department ID yet, wait for workflow approval
                delete body.departmentId;
            }
            
            // Update employee
            const updatedEmployee = { ...employees[employeeIndex], ...body, updatedAt: new Date().toISOString() };
            employees[employeeIndex] = updatedEmployee;
            localStorage.setItem(employeesKey, JSON.stringify(employees));
            
            return ok(updatedEmployee);
        }

        function deleteEmployee() {
            if (!isAuthorized(Role.Admin)) return unauthorized();
            
            const id = idFromUrl();
            // Check if employee exists
            if (!employees.find(x => x.id === id)) return notFound();
            
            // Delete employee and related workflows and requests
            employees = employees.filter(x => x.id !== id);
            workflows = workflows.filter(x => x.employeeId !== id);
            requests = requests.filter(x => x.employeeId !== id);
            
            // Update localStorage
            localStorage.setItem(employeesKey, JSON.stringify(employees));
            localStorage.setItem(workflowsKey, JSON.stringify(workflows));
            localStorage.setItem(requestsKey, JSON.stringify(requests));
            
            return ok();
        }

        // Department functions
        function getDepartments() {
            if (!isAuthenticated()) return unauthorized();
            
            // Make sure departments are properly retrieved from localStorage
            const storedDepartments = JSON.parse(localStorage.getItem(departmentsKey) || '[]');
            const storedEmployees = JSON.parse(localStorage.getItem(employeesKey) || '[]');
            
            // Ensure IDs are integers
            storedDepartments.forEach(dept => {
                if (typeof dept.id === 'string') {
                    dept.id = parseInt(dept.id);
                }
            });
            
            // Add employee count to each department
            const departmentsWithCounts = storedDepartments.map(dept => {
                const employeeCount = storedEmployees.filter(emp => emp.departmentId === dept.id).length;
                return {
                    ...dept,
                    employeeCount
                };
            });
            
            // Sort by name for better display
            departmentsWithCounts.sort((a, b) => a.name.localeCompare(b.name));
            
            return ok(departmentsWithCounts);
        }

        function getDepartmentById() {
            if (!isAuthenticated()) return unauthorized();
            
            const department = departments.find(x => x.id === idFromUrl());
            return department ? ok(department) : notFound();
        }

        function createDepartment() {
            if (!isAuthorized(Role.Admin)) return unauthorized();
            
            const department = body;
            
            // Check if department with same name already exists
            if (departments.find(x => x.name.toLowerCase() === department.name.toLowerCase())) {
                return error(`Department with name ${department.name} already exists`);
            }
            
            // Add department
            department.id = departments.length ? Math.max(...departments.map(x => x.id)) + 1 : 1;
            department.createdAt = new Date().toISOString();
            department.updatedAt = new Date().toISOString();
            departments.push(department);
            localStorage.setItem(departmentsKey, JSON.stringify(departments));
            
            return ok();
        }

        function updateDepartment() {
            if (!isAuthorized(Role.Admin)) return unauthorized();
            
            const id = idFromUrl();
            const departmentIndex = departments.findIndex(x => x.id === id);
            
            if (departmentIndex === -1) return notFound();
            
            // Check if updating to a name that already exists with different ID
            if (body.name && departments.some(x => x.name.toLowerCase() === body.name.toLowerCase() && x.id !== id)) {
                return error(`Department with name ${body.name} already exists`);
            }
            
            // Update department
            const updatedDepartment = { ...departments[departmentIndex], ...body, updatedAt: new Date().toISOString() };
            departments[departmentIndex] = updatedDepartment;
            localStorage.setItem(departmentsKey, JSON.stringify(departments));
            
            return ok(updatedDepartment);
        }

        function deleteDepartment() {
            if (!isAuthorized(Role.Admin)) return unauthorized();
            
            const id = idFromUrl();
            // Check if department exists
            if (!departments.find(x => x.id === id)) return notFound();
            
            // Check if department is in use by any employee
            if (employees.some(employee => employee.departmentId === id)) {
                return error('Cannot delete department that is assigned to employees');
            }
            
            // Delete department
            departments = departments.filter(x => x.id !== id);
            localStorage.setItem(departmentsKey, JSON.stringify(departments));
            
            return ok();
        }

        // Request functions
        function getRequests() {
            if (!isAuthenticated()) return unauthorized();
            
            // Filter requests based on user role
            const account = currentAccount();
            const requestsWithEmployeeDetails = requests.map(request => {
                // Find the employee for this request
                const employee = employees.find(e => e.id === parseInt(request.employeeId));
                
                // Add employee details to request
                return {
                    ...request,
                    employee: employee ? {
                        id: employee.id,
                        employeeId: employee.employeeId,
                        name: employee.firstName && employee.lastName ? 
                              `${employee.firstName} ${employee.lastName}` : 'Unknown',
                        email: employee.email
                    } : null
                };
            });
            
            if (isAuthorized(Role.Admin)) {
                // Admin can see all requests
                return ok(requestsWithEmployeeDetails);
            } else {
                // Regular users can only see their own requests
                // Find employee associated with current user
                const employee = employees.find(x => x.accountId === account.id);
                if (!employee) return ok([]);
                
                return ok(requestsWithEmployeeDetails.filter(request => 
                    request.employeeId === employee.id || 
                    `${request.employeeId}` === `${employee.id}`
                ));
            }
        }

        function getRequestById() {
            if (!isAuthenticated()) return unauthorized();
            
            const requestId = idFromUrl();
            const request = requests.find(x => x.id === requestId);
            
            if (!request) return notFound();
            
            // Check authorization
            const account = currentAccount();
            if (!isAuthorized(Role.Admin)) {
                // Regular users can only see their own requests
                const employee = employees.find(x => x.accountId === account.id);
                if (!employee || request.employeeId !== employee.id) {
                    return unauthorized();
                }
            }
            
            return ok(request);
        }

        function createRequest() {
            if (!isAuthenticated()) return unauthorized();
            
            const request = body;
            const account = currentAccount();
            
            // Validate employee access
            if (!isAuthorized(Role.Admin)) {
                const employee = employees.find(x => x.accountId === account.id);
                if (!employee) return unauthorized();
                
                // Set employee ID to current user's employee record
                request.employeeId = employee.id;
            } else if (typeof request.employeeId === 'string') {
                // Convert string employeeId to integer if needed
                request.employeeId = parseInt(request.employeeId);
            }
            
            // Add request
            request.id = requests.length ? Math.max(...requests.map(x => x.id)) + 1 : 1;
            request.status = 'Pending';
            request.createdAt = new Date().toISOString();
            request.updatedAt = new Date().toISOString();
            
            // Assign IDs to items if they exist
            if (request.items && Array.isArray(request.items)) {
                request.items = request.items.map((item, index) => ({
                    ...item,
                    id: index + 1,
                    status: item.status || 'Pending'
                }));
            }
            
            requests.push(request);
            localStorage.setItem(requestsKey, JSON.stringify(requests));
            
            // Create a workflow for this request
            const employee = employees.find(e => e.id === request.employeeId);
            const department = departments.find(d => d.id === employee?.departmentId);
            
            const workflow = {
                id: workflows.length ? Math.max(...workflows.map(x => x.id)) + 1 : 1,
                employeeId: request.employeeId, // Use the integer employeeId
                type: 'Request',
                status: 'Pending',
                details: {
                    requestId: request.id,
                    message: `New ${request.type} request created`,
                    // Store all request data needed for display
                    requestType: request.type,
                    requesterId: request.employeeId,
                    items: request.items || []
                },
                created: new Date().toISOString(),
                updated: new Date().toISOString()
            };
            
            workflows.push(workflow);
            localStorage.setItem(workflowsKey, JSON.stringify(workflows));
            
            return ok(request);
        }

        function updateRequest() {
            if (!isAuthenticated()) return unauthorized();
            
            const requestId = idFromUrl();
            const requestIndex = requests.findIndex(x => x.id === requestId);
            
            if (requestIndex === -1) return notFound();
            
            const account = currentAccount();
            const existingRequest = requests[requestIndex];
            let updatedRequest;
            
            // Check authorization
            if (!isAuthorized(Role.Admin)) {
                const employee = employees.find(x => x.accountId === account.id);
                if (!employee || existingRequest.employeeId !== employee.id) {
                    return unauthorized();
                }
                
                // Regular users can only update certain fields
                updatedRequest = { ...existingRequest };
                
                const allowedFields = ['title', 'description', 'type'];
                allowedFields.forEach(field => {
                    if (body[field] !== undefined) {
                        updatedRequest[field] = body[field];
                    }
                });
            } else {
                // Admins can update any field
                updatedRequest = { 
                    ...existingRequest,
                    ...body
                };
            }
            
            // Process items to ensure all have valid IDs
            if (updatedRequest.items && Array.isArray(updatedRequest.items)) {
                // Get maximum existing ID
                const maxId = updatedRequest.items
                    .filter(item => item.id !== null && item.id !== undefined)
                    .reduce((max, item) => Math.max(max, item.id), 0);
                
                // Assign new IDs to items with null IDs
                let nextId = maxId + 1;
                updatedRequest.items = updatedRequest.items.map(item => {
                    if (item.id === null || item.id === undefined) {
                        return {
                            ...item,
                            id: nextId++,
                            status: item.status || 'Pending'
                        };
                    }
                    return item;
                });
            }
            
            // Update timestamp
            updatedRequest.updatedAt = new Date().toISOString();
            
            // Save the updated request
                requests[requestIndex] = updatedRequest;
            localStorage.setItem(requestsKey, JSON.stringify(requests));
            
            // Update related workflows
            const relatedWorkflows = workflows.filter(w => 
                (w.type === 'Request' || w.type === 'Request Approval') && 
                w.details && 
                w.details.requestId === requestId
            );
            
            if (relatedWorkflows.length > 0) {
                relatedWorkflows.forEach(workflow => {
                    // Update workflow details based on the new request
                    if (workflow.type === 'Request Approval' || workflow.type === 'Request') {
                        workflow.details = {
                            ...workflow.details,
                            // Update title if workflow has been converted to Request Approval format
                            title: workflow.type === 'Request Approval' ? 
                                `Review ${updatedRequest.type} request #${updatedRequest.id} with ${updatedRequest.items?.length || 0} items` : 
                                workflow.details.title,
                            // Always include the latest items from the request
                            items: updatedRequest.items || []
                        };
                        workflow.updated = new Date().toISOString();
                    }
                });
                
                localStorage.setItem(workflowsKey, JSON.stringify(workflows));
            }
            
            return ok(updatedRequest);
        }

        function updateRequestStatus() {
            if (!isAuthenticated()) return unauthorized();
            
            const requestId = idFromUrl();
            const requestIndex = requests.findIndex(x => x.id === requestId);
            
            if (requestIndex === -1) return notFound();
            
            const account = currentAccount();
            const existingRequest = requests[requestIndex];
            
            // Check authorization
            if (!isAuthorized(Role.Admin)) {
                const employee = employees.find(x => x.accountId === account.id);
                if (!employee || existingRequest.employeeId !== employee.id) {
                    return unauthorized();
                }
            }
            
            // Store old status for comparison
            const oldStatus = existingRequest.status;
            
            // Update request status
            const updatedRequest = { ...existingRequest, status: body.status, updatedAt: new Date().toISOString() };
            requests[requestIndex] = updatedRequest;
            
            // Create workflow entry if status changed
            if (body.status && oldStatus !== body.status) {
                // Create a workflow for the status change
                const workflow = {
                    id: workflows.length ? Math.max(...workflows.map(x => x.id)) + 1 : 1,
                    employeeId: existingRequest.employeeId,
                    type: 'Request Status Update',
                    status: 'Completed',
                    details: {
                        requestId: existingRequest.id,
                        requestType: existingRequest.type,
                        oldStatus: oldStatus,
                        newStatus: body.status,
                        updatedBy: account.role,
                        message: `Request #${existingRequest.id} status changed from ${oldStatus} to ${body.status}`
                    },
                    created: new Date().toISOString()
                };
                
                workflows.push(workflow);
                localStorage.setItem(workflowsKey, JSON.stringify(workflows));
            }
            
            localStorage.setItem(requestsKey, JSON.stringify(requests));
            return ok(updatedRequest);
        }

        function deleteRequest() {
            if (!isAuthenticated()) return unauthorized();
            
            const requestId = idFromUrl();
            const request = requests.find(x => x.id === requestId);
            
            if (!request) return notFound();
            
            // Check authorization
            const account = currentAccount();
            if (!isAuthorized(Role.Admin)) {
                const employee = employees.find(x => x.accountId === account.id);
                if (!employee || request.employeeId !== employee.id) {
                    return unauthorized();
                }
            }
            
            // Delete request
            requests = requests.filter(x => x.id !== requestId);
            localStorage.setItem(requestsKey, JSON.stringify(requests));
            
            return ok();
        }

        // Workflow functions
        function getWorkflows() {
            if (!isAuthenticated()) return unauthorized();
            
            // Convert any string employeeIds to integers
            const normalizedWorkflows = workflows.map(w => ({
                ...w,
                employeeId: typeof w.employeeId === 'string' ? parseInt(w.employeeId) : w.employeeId
            }));
            
            // Filter out duplicate workflows
            const uniqueWorkflows = [];
            const seen = new Set();
            
            normalizedWorkflows.forEach(w => {
                // Create a key based on type, employeeId, and requestId (for requests)
                let key = `${w.type}-${w.employeeId}`;
                
                // For requests, include the requestId in the key to ensure uniqueness
                if (w.type === 'Request' && w.details?.requestId) {
                    key += `-${w.details.requestId}`;
                } else if (w.type === 'Onboarding') {
                    // For onboarding, include departmentId if available
                    key += `-${w.details?.departmentId || ''}`;
                }
                
                // Skip Request Status Update workflows completely
                if (w.type === 'Request Status Update') {
                    return;
                }
                
                // Skip the basic "Request" type workflows, we only want to show the approval view
                if (w.type === 'Request' && w.details?.message?.includes('New') && w.details?.message?.includes('created')) {
                    return;
                }
                
                // Check if we've seen this key before - only add if it's new
                    if (!seen.has(key)) {
                        seen.add(key);
                    
                    // For the Request Approval workflow, augment with more details
                    if (w.type === 'Request') {
                        // Find the corresponding request
                        const request = requests.find(r => r.id === w.details?.requestId);
                        if (request) {
                            // Update the workflow type to distinguish it
                            w.type = 'Request Approval';
                            // Update details to show more information about the request
                            w.details = {
                                ...w.details,
                                title: `Review ${request.type} request #${request.id} with ${request.items?.length || 0} items`
                            };
                        }
                    }
                    
                    uniqueWorkflows.push(w);
                }
            });
            
            // Add employee details to workflows
            const workflowsWithEmployees = uniqueWorkflows.map(workflow => {
                const employee = employees.find(e => e.id === workflow.employeeId);
                return {
                    ...workflow,
                    employee: employee ? { 
                        id: employee.id,
                        employeeId: employee.employeeId,
                        firstName: employee.firstName,
                        lastName: employee.lastName,
                        email: employee.email
                    } : null
                };
            });
            
            return ok(workflowsWithEmployees);
        }

        function getWorkflowsByEmployeeId() {
            if (!isAuthenticated()) return unauthorized();
            
            // Extract employee ID from URL
            const urlParts = url.split('/');
            const employeeId = parseInt(urlParts[urlParts.length - 1]);
            
            if (isNaN(employeeId)) return error('Invalid employee ID');
            
            // Convert any string employeeIds to integers and deduplicate
            const normalizedWorkflows = workflows.map(w => ({
                ...w,
                employeeId: typeof w.employeeId === 'string' ? parseInt(w.employeeId) : w.employeeId
            }));
            
            // Filter out duplicate onboarding workflows
            const uniqueWorkflows = [];
            const seen = new Set();
            
            normalizedWorkflows.forEach(w => {
                // Skip workflows that don't match the requested employeeId
                if (w.employeeId !== employeeId) {
                    return;
                }
                
                // Create a key based on type and departmentId (for onboarding)
                let key = `${w.type}`;
                
                if (w.type === 'Request' && w.details?.requestId) {
                    key += `-${w.details.requestId}`;
                } else if (w.type === 'Onboarding') {
                    key += `-${w.details?.departmentId || ''}`;
                }
                
                // Skip Request Status Update workflows
                if (w.type === 'Request Status Update') {
                    return;
                }
                
                // Skip the basic "Request" type workflows, we only want to show the approval view
                if (w.type === 'Request' && w.details?.message?.includes('New') && w.details?.message?.includes('created')) {
                    return;
                }
                
                // For onboarding, only keep one per department
                if (w.type === 'Onboarding') {
                    if (!seen.has(key)) {
                        seen.add(key);
                        uniqueWorkflows.push(w);
                    }
                } else {
                    // For the Request Approval workflow, augment with more details
                    if (w.type === 'Request') {
                        // Find the corresponding request
                        const request = requests.find(r => r.id === w.details?.requestId);
                        if (request) {
                            // Update the workflow type to distinguish it
                            w.type = 'Request Approval';
                            // Update details to show more information about the request
                            w.details = {
                                ...w.details,
                                title: `Review ${request.type} request #${request.id} with ${request.items?.length || 0} items`
                            };
                        }
                    }
                    
                    uniqueWorkflows.push(w);
                }
            });
            
            // Sort by created date (descending)
            uniqueWorkflows.sort((a, b) => {
                const dateA = new Date(a.created || 0).getTime();
                const dateB = new Date(b.created || 0).getTime();
                return dateB - dateA;
            });
            
            return ok(uniqueWorkflows);
        }

        function getWorkflowById() {
            if (!isAuthenticated()) return unauthorized();
            
            const workflowId = idFromUrl();
            const workflow = workflows.find(x => x.id === workflowId);
            
            if (!workflow) return notFound();
            
            return ok(workflow);
        }

        function createWorkflow() {
            if (!isAuthenticated()) return unauthorized();
            
            const workflow = body;
            
            // Ensure employeeId is an integer
            if (workflow.employeeId) {
                workflow.employeeId = typeof workflow.employeeId === 'string' ? 
                    parseInt(workflow.employeeId) : workflow.employeeId;
            }
            
            // Validate employee ID
            if (!workflow.employeeId || isNaN(workflow.employeeId)) {
                return error('Invalid employee ID');
            }
            
            const employeeExists = employees.some(e => e.id === workflow.employeeId);
            if (!employeeExists) {
                return error(`Employee with ID ${workflow.employeeId} does not exist`);
            }
            
            // If this is a transfer workflow, validate the department ID
            if (workflow.type === 'Transfer' && workflow.details && workflow.details.departmentId) {
                // Ensure departmentId is an integer
                workflow.details.departmentId = typeof workflow.details.departmentId === 'string' ? 
                    parseInt(workflow.details.departmentId) : workflow.details.departmentId;
                
                // Check if department exists
                const departmentExists = departments.some(d => d.id === workflow.details.departmentId);
                if (!departmentExists) {
                    return error(`Department with ID ${workflow.details.departmentId} does not exist`);
                }
            }
            
            // Add workflow
            workflow.id = workflows.length ? Math.max(...workflows.map(x => x.id)) + 1 : 1;
            workflow.status = workflow.status || 'Pending';
            workflow.created = new Date().toISOString();
            workflow.updated = new Date().toISOString();
            workflows.push(workflow);
            localStorage.setItem(workflowsKey, JSON.stringify(workflows));
            
            // If this is an approved transfer request, update employee department
            if (workflow.type === 'Transfer' && workflow.status === 'Approved' && workflow.details && workflow.details.departmentId) {
                const employeeIndex = employees.findIndex(e => e.id === workflow.employeeId);
                if (employeeIndex !== -1) {
                    // Store old department for reference
                    const oldDepartmentId = employees[employeeIndex].departmentId;
                    const oldDepartment = departments.find(d => d.id === oldDepartmentId);
                    const newDepartment = departments.find(d => d.id === workflow.details.departmentId);
                    
                    // Update employee department
                    employees[employeeIndex].departmentId = workflow.details.departmentId;
                    employees[employeeIndex].updatedAt = new Date().toISOString();
                    localStorage.setItem(employeesKey, JSON.stringify(employees));
                    
                    // Update workflow details with department names for better display
                    workflow.details.oldDepartmentName = oldDepartment ? oldDepartment.name : 'None';
                    workflow.details.newDepartmentName = newDepartment ? newDepartment.name : 'Unknown';
                    workflow.details.message = `Transferred from ${workflow.details.oldDepartmentName} to ${workflow.details.newDepartmentName}`;
                    localStorage.setItem(workflowsKey, JSON.stringify(workflows));
                }
            }
            
            return ok(workflow);
        }

        function updateWorkflowStatus() {
            if (!isAuthenticated()) return unauthorized();
            
            const workflowId = idFromUrl();
            if (workflowId === null) return notFound();
            
            const workflowIndex = workflows.findIndex(x => x.id === workflowId);
            
            if (workflowIndex === -1) return notFound();
            
            // Update workflow status
            const oldStatus = workflows[workflowIndex].status;
            workflows[workflowIndex].status = body.status;
            workflows[workflowIndex].updated = new Date().toISOString();
            localStorage.setItem(workflowsKey, JSON.stringify(workflows));
            
            const workflow = workflows[workflowIndex];
            
            // Handle Transfer workflows when approved
            if (workflow.type === 'Transfer' && body.status === 'Approved' && oldStatus !== 'Approved') {
                const employeeIndex = employees.findIndex(e => e.id === workflow.employeeId);
                if (employeeIndex !== -1 && workflow.details && workflow.details.departmentId) {
                    // Store old department for reference
                    const oldDepartmentId = employees[employeeIndex].departmentId;
                    const oldDepartment = departments.find(d => d.id === oldDepartmentId);
                    const newDepartment = departments.find(d => d.id === workflow.details.departmentId);
                    
                    // Update employee department
                    employees[employeeIndex].departmentId = workflow.details.departmentId;
                    employees[employeeIndex].updatedAt = new Date().toISOString();
                    localStorage.setItem(employeesKey, JSON.stringify(employees));
                    
                    // Update workflow details with department names for better display
                    workflow.details.oldDepartmentName = oldDepartment ? oldDepartment.name : 'None';
                    workflow.details.newDepartmentName = newDepartment ? newDepartment.name : 'Unknown';
                    workflow.details.message = `Transferred from ${workflow.details.oldDepartmentName} to ${workflow.details.newDepartmentName}`;
                    localStorage.setItem(workflowsKey, JSON.stringify(workflows));
                }
            }
            
            // Handle Request workflows when approved
            if ((workflow.type === 'Request' || workflow.type === 'Request Approval') && body.status === 'Approved' && oldStatus !== 'Approved' && workflow.details && workflow.details.requestId) {
                const requestId = workflow.details.requestId;
                const requestIndex = requests.findIndex(r => r.id === requestId);
                
                if (requestIndex !== -1) {
                    // Update the request status
                    requests[requestIndex].status = 'Approved';
                    requests[requestIndex].updatedAt = new Date().toISOString();
                    
                    // Also update the status of all items in the request
                    if (requests[requestIndex].items && Array.isArray(requests[requestIndex].items)) {
                        requests[requestIndex].items = requests[requestIndex].items.map(item => ({
                            ...item,
                            status: 'Approved'
                        }));
                    }
                    
                    localStorage.setItem(requestsKey, JSON.stringify(requests));
                    
                    // Update the workflow details to include the latest items
                    if (workflow.type === 'Request Approval') {
                        workflow.details = {
                            ...workflow.details,
                            items: requests[requestIndex].items || []
                        };
                        localStorage.setItem(workflowsKey, JSON.stringify(workflows));
                    }
                }
            }
            
            return ok(workflows[workflowIndex]);
        }

        function deleteWorkflow() {
            if (!isAuthenticated()) return unauthorized();
            
            const workflowId = idFromUrl();
            const workflow = workflows.find(x => x.id === workflowId);
            
            if (!workflow) return notFound();
            
            // Delete workflow
            workflows = workflows.filter(x => x.id !== workflowId);
            localStorage.setItem(workflowsKey, JSON.stringify(workflows));
            
            return ok();
        }

        // helper functions

        function ok(body?) {
            return of(new HttpResponse({ status: 200, body }))
                .pipe(delay(500)); //delay observable to simulate server api call
        }

        function error(message) {
            return throwError({ error: { message } })
                .pipe(materialize(), delay(500), dematerialize());
            //call materialize and dematerialize to ensure delay even if an error is thrown 
        }

        function unauthorized() {
            return throwError({ status: 401, error: { message: 'Unauthorized' } })
                .pipe(materialize(), delay(500), dematerialize());
        }
        
        function notFound() {
            return throwError({ status: 404, error: { message: 'Not Found' } })
                .pipe(materialize(), delay(500), dematerialize());
        }

        function basicDetails(account) {
            const { id, title, firstName, lastName, email, role, dateCreated, isVerified, status, acceptTerms } = account;
            return { id, title, firstName, lastName, email, role, dateCreated, isVerified, status, acceptTerms };
        }

        function isAuthenticated() {
            return !!currentAccount();
        }

        function isAuthorized(role) {
            const account = currentAccount();
            if (!account) return false;
            return account.role === role;
        }

        function idFromUrl() {
            const urlParts = url.split('/');
            
            // Handle special case for workflows/:id/status endpoint
            if (urlParts[urlParts.length - 1] === 'status') {
                const id = parseInt(urlParts[urlParts.length - 2]);
                if (isNaN(id)) {
                    console.error('Invalid ID in URL:', urlParts[urlParts.length - 2]);
                    return null;
                }
                return id;
            }
            
            const id = parseInt(urlParts[urlParts.length - 1]);
            if (isNaN(id)) {
                console.error('Invalid ID in URL:', urlParts[urlParts.length - 1]);
                return null;
            }
            return id;
        }

        function newAccountId() {
            return accounts.length ? Math.max(...accounts.map(x => x.id || 0)) + 1 : 1;
        }

        function currentAccount() {
            // check if jwt token is in auth header
            const authHeader = headers.get('Authorization');
            if (!authHeader || !authHeader.startsWith('Bearer fake-jwt-token')) return;

            try {
                // check if token is expired
                const jwtParts = authHeader.split('.');
                if (jwtParts.length !== 2) return; // Invalid format
                
                const jwtToken = JSON.parse(atob(jwtParts[1]));
            const tokenExpired = Date.now() > (jwtToken.exp * 1000);
            if (tokenExpired) return;

            const account = accounts.find(x => x.id === jwtToken.id);
            return account;
            } catch (error) {
                console.error('Error parsing JWT token:', error);
                return;
            }
        }

        function generateJwtToken(account) {
            // create token that expires in 15 minutes
            const tokenPayload = {
                exp: Math.round(new Date(Date.now() + 15 * 60 * 1000).getTime() / 1000),
                id: account.id,
            }
            // Format must be exactly as expected by the frontend: fake-jwt-token.<base64-encoded-payload>
            const base64Payload = btoa(JSON.stringify(tokenPayload));
            return `fake-jwt-token.${base64Payload}`;
        }

        function generateRefreshToken() {
            const token = new Date().getTime().toString();

            // add token cookie that expires in 7 days
            const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toUTCString();
            document.cookie = `fakeRefreshToken=${token}; expires=${expires}; path=/`;

            return token;
        }

        function getRefreshToken() {
            // get refresh token from cookie
            return (document.cookie.split(';').find(x => x.includes('fakeRefreshToken')) || '=').split('=')[1];
        }

        function getUnlinkedAccounts() {
            if (!isAuthenticated()) return unauthorized();
            
            // Get all account IDs that are already linked to employees
            const linkedAccountIds = employees.map(e => e.accountId).filter(id => id !== undefined && id !== null);
            
            // Filter active accounts that aren't already linked to an employee
            const unlinkedAccounts = accounts.filter(a => 
                a.status === 'Active' && 
                !linkedAccountIds.includes(a.id)
            );
            
            return ok(unlinkedAccounts.map(x => basicDetails(x)));
        }

        function getUsers() {
            if (!isAuthenticated()) return unauthorized();
            
            // Get the current accounts and employees from localStorage
            const storedAccounts = JSON.parse(localStorage.getItem(accountsKey) || '[]');
            const storedEmployees = JSON.parse(localStorage.getItem(employeesKey) || '[]');
            
            // Get all account IDs that are already linked to employees
            const linkedAccountIds = storedEmployees
                .filter(e => e.accountId !== undefined && e.accountId !== null)
                .map(e => e.accountId);
            
            // Only return active, verified accounts that aren't already linked to an employee
            const unlinkedAccounts = storedAccounts.filter(x => 
                x.status === 'Active' && 
                x.isVerified && 
                !linkedAccountIds.includes(x.id)
            );
            
            return ok(unlinkedAccounts.map(x => ({
                id: x.id,
                email: x.email, 
                firstName: x.firstName,
                lastName: x.lastName,
                role: x.role
            })));
        }

        function transferEmployee() {
            if (!isAuthenticated()) return unauthorized();
            
            // Extract employee ID from URL
            const urlParts = url.split('/');
            const employeeId = parseInt(urlParts[urlParts.length - 2]);
            
            if (isNaN(employeeId)) {
                return error('Invalid employee ID');
            }
            
            // Find the employee
            const employeeIndex = employees.findIndex(e => e.id === employeeId);
            if (employeeIndex === -1) {
                return error(`Employee with ID ${employeeId} not found`);
            }
            
            // Get the department ID from the request body
            const departmentId = typeof body.departmentId === 'string' ? 
                parseInt(body.departmentId) : body.departmentId;
            
            if (!departmentId || isNaN(departmentId)) {
                return error('Invalid department ID');
            }
            
            // Check if department exists
            const newDepartment = departments.find(d => d.id === departmentId);
            if (!newDepartment) {
                return error(`Department with ID ${departmentId} not found`);
            }
            
            // Get the old department
            const oldDepartmentId = employees[employeeIndex].departmentId;
            const oldDepartment = departments.find(d => d.id === oldDepartmentId);
            
            // Create a transfer workflow
            const workflow = {
                id: workflows.length ? Math.max(...workflows.map(x => x.id)) + 1 : 1,
                employeeId: employeeId,
                type: 'Transfer',
                status: 'Pending',
                details: {
                    oldDepartmentId: oldDepartmentId,
                    departmentId: departmentId,
                    oldDepartmentName: oldDepartment ? oldDepartment.name : 'None',
                    newDepartmentName: newDepartment.name,
                    message: `Transfer from ${oldDepartment ? oldDepartment.name : 'None'} to ${newDepartment.name}`
                },
                created: new Date().toISOString(),
                updated: new Date().toISOString()
            };
            
            workflows.push(workflow);
            localStorage.setItem(workflowsKey, JSON.stringify(workflows));
            
            return ok({
                message: `Transfer request created successfully. Workflow ID: ${workflow.id}`,
                workflowId: workflow.id
            });
        }

    }
}

export const fakeBackendProvider = {
    // use fake backend in place of Http service for backend-less development
    provide: HTTP_INTERCEPTORS,
    useClass: FakeBackendInterceptor,
    multi: true
};
