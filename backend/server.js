require('rootpath')();
require('dotenv').config();
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const errorHandler = require('./_middleware/error_handler');
const http = require('http');

// Parse JSON and URL-encoded data
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// CORS configuration
app.use((req, res, next) => {
    // Log the origin for debugging
    console.log(`Request origin: ${req.headers.origin}`);
    next();
});

app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (like mobile apps, curl, etc)
        if (!origin) return callback(null, true);
        
        // Define allowed origins
        const allowedOrigins = [
            'https://user-management-system-angular-tm8z.vercel.app',
            'https://user-management-system-angular.vercel.app',
            'https://user-management-system-angular-froillan123.vercel.app',
            'http://localhost:4200',
            'http://localhost:3000',
            'http://127.0.0.1:4200'
        ];
        
        // Check if the origin is allowed
        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            console.log(`CORS blocked request from: ${origin}`);
            callback(new Error('Not allowed by CORS'), false);
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Add additional headers to handle preflight requests
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Credentials', 'true');
    
    const allowedOrigins = [
        'https://user-management-system-angular-tm8z.vercel.app',
        'https://user-management-system-angular.vercel.app',
        'https://user-management-system-angular-froillan123.vercel.app',
        'http://localhost:4200',
        'http://localhost:3000',
        'http://127.0.0.1:4200'
    ];
    
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
    }
    
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    next();
});

// Handle OPTIONS preflight requests
app.options('*', (req, res) => {
    res.sendStatus(200);
});

// API routes
app.use('/accounts', require('./accounts/accounts.controller'));
app.use('/accounts/analytics', require('./accounts/analytics.controller'));

// Swagger docs route - add after API routes
try {
    app.use('/api-docs', require('./_helpers/swagger'));
    console.log('Swagger UI loaded successfully');
} catch (error) {
    console.error('Failed to load Swagger UI:', error);
    app.use('/api-docs', (req, res) => {
        res.status(500).send('API Documentation temporarily unavailable');
    });
}

// Global error handler
app.use(errorHandler);

// Create HTTP server
const server = http.createServer(app);

// Initialize Socket.IO
const socketModule = require('./_helpers/socket');
socketModule.init(server);

// Start server
const port = process.env.NODE_ENV === 'production' ? (process.env.PORT || 80) : 4000;
server.listen(port, () => {
    console.log('Server listening on port ' + port);
    console.log('API Documentation available at /api-docs');
    console.log('WebSocket server initialized');
});