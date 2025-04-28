import { Injectable } from '@angular/core';
import { HttpRequest, HttpResponse, HttpHandler, HttpEvent, HttpInterceptor, HTTP_INTERCEPTORS, HttpHeaders } from '@angular/common/http';
import { Observable, of, throwError } from 'rxjs';
import { delay, materialize, dematerialize } from 'rxjs/operators';

import { AlertService } from '../../app/_services';
import { Role } from '../../app/_models';

const accountsKey = 'angular-10-signup-verification-boilerplate-accounts';
let accounts = JSON.parse(localStorage.getItem(accountsKey) || '[]');

// Patch old accounts in localStorage to ensure refreshTokens exist and add online status
accounts = accounts.map(acc => {
    if (!acc.refreshTokens) acc.refreshTokens = [];
    if (acc.isOnline === undefined) acc.isOnline = Math.random() > 0.5;
    if (acc.lastActive === undefined) acc.lastActive = new Date().toISOString();
    if (acc.acceptTerms === undefined) acc.acceptTerms = true;
    return acc;
});
localStorage.setItem(accountsKey, JSON.stringify(accounts));

@Injectable()
export class FakeBackendInterceptor implements HttpInterceptor {
    constructor(private alertService: AlertService) { }

    intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
        const { url, method, headers, body } = request;
        const alertService = this.alertService;

        return handleRoute();

        function handleRoute() {
            switch (true) {
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

            return ok({
                ...basicDetails(account),
                jwtToken: generateJwtToken(account)
            });
        }


        function refreshToken() {
            const refreshToken = getRefreshToken();

            if (!refreshToken) return unauthorized();

            const account = accounts.find(x => x.refreshTokens && x.refreshTokens.includes(refreshToken));

            if (!account) return unauthorized();

            // Update active status
            account.lastActive = new Date().toISOString();

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
            
            if (accounts.length === 0) {
                // First user is Admin
                account.role = Role.Admin;
                account.isVerified = true;
                account.status = 'Active';
                account.id = newAccountId();
                accounts.push(account);
                localStorage.setItem(accountsKey, JSON.stringify(accounts));
                
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
            const account = accounts.find(x => !!x.verificationToken && x.verificationToken === token);

            if (!account) return error('Verification failed');

            account.isVerified = true;
            account.status = 'Active';
            localStorage.setItem(accountsKey, JSON.stringify(accounts));

            // Show success message
            setTimeout(() => {
                alertService.success('Email verified successfully! Your account is now active and you can log in.', { autoClose: true });
            }, 1000);

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

            //check if token is expired
            const jwtToken = JSON.parse(atob(authHeader.split('.')[1]));
            const tokenExpired = Date.now() > (jwtToken.exp * 1000);
            if (tokenExpired) return;

            const account = accounts.find(x => x.id === jwtToken.id);
            return account;
        }

        function generateJwtToken(account) {
            // create token that expires in 15 minutes
            const tokenPayload = {
                exp: Math.round(new Date(Date.now() + 15 * 60 * 1000).getTime() / 1000),
                id: account.id,
            }
            return `fake-jwt-token.${btoa(JSON.stringify(tokenPayload))}`;
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

    }
}

export const fakeBackendProvider = {
    // use fake backend in place of Http service for backend-less development
    provide: HTTP_INTERCEPTORS,
    useClass: FakeBackendInterceptor,
    multi: true
};
