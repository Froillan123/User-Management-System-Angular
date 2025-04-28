// Dynamic environment configuration based on hostname
const hostname = window.location.hostname;
const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1';

export const environment = {
    production: false,
    apiUrl: isLocalhost 
        ? 'http://localhost:4000/accounts'
        : 'https://user-management-system-angular.onrender.com/accounts',
    wsUrl: isLocalhost
        ? 'ws://localhost:4000'
        : 'wss://user-management-system-angular.onrender.com'
};

