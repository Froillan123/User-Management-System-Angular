// Dynamic environment configuration based on hostname
const hostname = window.location.hostname;
const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1';
const isVercel = hostname.includes('vercel.app');

export const environment = {
    production: true,
    apiUrl: isLocalhost 
        ? 'http://localhost:4000/accounts'
        : 'https://user-management-system-angular.onrender.com/accounts',
    wsUrl: isLocalhost
        ? 'ws://localhost:4000'
        : 'wss://user-management-system-angular.onrender.com',
    cookieDomain: isLocalhost 
        ? undefined 
        : isVercel 
            ? '.vercel.app'
            : '.onrender.com'
};
