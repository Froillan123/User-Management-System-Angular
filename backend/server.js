require('rootpath')();
require('dotenv').config();
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const errorHandler = require('./_middleware/error_handler');

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// CORS configuration
app.use(cors({
    origin: ['http://localhost:4200', 'https://user-management-system-angular.netlify.app', 'https://user-management-system-angular.onrender.com'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin']
}));

// Enable pre-flight requests for all routes using regex pattern instead of wildcard
// This fixes the "Missing parameter name" error in Express 5
app.options(/(.*)/, cors({
    origin: ['http://localhost:4200', 'https://user-management-system-angular.netlify.app', 'https://user-management-system-angular.onrender.com'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin']
}));

// Set secure cookie options
app.use((req, res, next) => {
    if (req.cookies.refreshToken) {
        res.cookie('refreshToken', req.cookies.refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'none',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });
    }
    next();
});

// Add request logging middleware
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  
  // Log headers if this is an API request
  if (req.url.includes('/accounts')) {
    console.log('Headers:', JSON.stringify(req.headers));
    
    // Log Authorization header if present
    if (req.headers.authorization) {
      console.log(`Authorization: ${req.headers.authorization}`);
    }
  }
  
  next();
});

// api routes
app.use('/accounts', require('./accounts/accounts.controller'));

// Add a test endpoint
app.get('/test', (req, res) => {
  console.log('Test endpoint accessed');
  res.json({ 
    status: 'success', 
    message: 'API is working correctly', 
    timestamp: new Date().toISOString(),
    env: process.env.NODE_ENV || 'development',
    headers: req.headers,
    cookies: req.cookies,
    ip: req.ip
  });
});

// Add connection test endpoint
app.get('/connection-test', (req, res) => {
  console.log('Connection test endpoint accessed');
  const authHeader = req.headers.authorization || 'No Authorization header';
  
  res.json({
    status: 'connected',
    message: 'Connection test successful',
    auth: authHeader.startsWith('Bearer ') ? 'Bearer token present' : 'No valid bearer token',
    cookies: Object.keys(req.cookies).length > 0 ? 'Cookies present' : 'No cookies',
    cors: 'CORS headers enabled',
    timestamp: new Date().toISOString()
  });
});

// Catch-all route for handling undefined routes - this uses a regexp directly instead of a string
// Express 5 requires named parameters for wildcards
app.use(/(.*)/, (req, res) => {
    res.status(404).json({ message: 'Not Found' });
});

// global error handler
app.use(errorHandler);

// start server
const port = process.env.NODE_ENV === 'production' ? (process.env.PORT || 80) : 4000;
app.listen(port, () => {
    console.log('Server listening on port ' + port);
});