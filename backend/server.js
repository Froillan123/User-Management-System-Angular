require('rootpath')();
require('dotenv').config();
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const errorHandler = require('./_middleware/error_handler');
const http = require('http');

app.use('/api-docs', require('./_helpers/swagger'));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// CORS configuration
app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (like mobile apps, curl, etc)
        if (!origin) return callback(null, true);
        
        // Define allowed origins
        const allowedOrigins = process.env.NODE_ENV === 'production'
            ? [
                process.env.FRONTEND_URL,
                'https://user-management-system-angular.vercel.app',
                'https://user-management-system-angular-tm8z.vercel.app',
                'https://user-management-system-angular-froillan123.vercel.app'
              ]
            : ['http://localhost:4200', 'http://localhost:3000', 'http://127.0.0.1:4200'];
        
        // Check if the origin is allowed
        if (allowedOrigins.indexOf(origin) === -1) {
            console.log(`CORS blocked request from: ${origin}`);
            return callback(new Error('CORS policy: Origin not allowed'), false);
        }
        
        return callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// api routes
app.use('/accounts', require('./accounts/accounts.controller'));
app.use('/accounts/analytics', require('./accounts/analytics.controller'));

// swagger docs route
app.use('/api-docs', require('./_helpers/swagger'));

// global error handler
app.use(errorHandler);

// Create HTTP server
const server = http.createServer(app);

// Initialize Socket.IO
const socketModule = require('./_helpers/socket');
socketModule.init(server);

// start server
const port = process.env.NODE_ENV === 'production' ? (process.env.PORT || 80) : 4000;
server.listen(port, () => {
    console.log('Server listening on port ' + port);
    console.log('API Documentation available at /api-docs');
    console.log('WebSocket server initialized');
});