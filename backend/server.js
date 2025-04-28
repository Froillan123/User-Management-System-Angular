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
    origin: process.env.NODE_ENV === 'production' 
        ? process.env.FRONTEND_URL 
        : 'http://localhost:4200',
    credentials: true
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