// Dynamic environment configuration based on hostname
const hostname = window.location.hostname;
const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1';

export const environment = {
    production: true,
    apiUrl: isLocalhost 
        ? 'http://localhost:4000/accounts'
        : 'https://user-management-system-backend.vercel.app/accounts',
    wsUrl: isLocalhost
        ? 'ws://localhost:4000'
        : 'wss://user-management-system-backend.vercel.app',
    cookieDomain: isLocalhost ? undefined : '.vercel.app'
};
