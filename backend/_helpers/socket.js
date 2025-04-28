const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const config = require('../config.json');
const db = require('./db');

// Determine environment
const env = process.env.NODE_ENV === 'production' ? 'production' : 'development';
const envConfig = config[env];

let io;
const connectedUsers = new Map(); // Map of userId -> socketId

// Allowed origins based on environment
const getAllowedOrigins = () => {
    return process.env.NODE_ENV === 'production' 
        ? [
            'https://user-management-system-angular-tm8z.vercel.app',
            'https://user-management-system-angular.vercel.app',
            'https://user-management-system-angular-froillan123.vercel.app'
          ]
        : ['http://localhost:4200', 'http://localhost:3000', 'http://127.0.0.1:4200'];
};

module.exports = {
    init: (server) => {
        io = new Server(server, {
            cors: {
                origin: getAllowedOrigins(),
                methods: ['GET', 'POST'],
                credentials: true
            }
        });

        io.use(async (socket, next) => {
            try {
                // Get token from handshake auth
                const token = socket.handshake.auth.token;
                if (!token) {
                    return next(new Error('Authentication error: Token missing'));
                }

                // Verify token
                const tokenParts = token.split('.');
                if (tokenParts.length !== 3) {
                    return next(new Error('Invalid token format'));
                }

                try {
                    // Verify JWT token
                    const decoded = jwt.verify(token, envConfig.secret);
                    socket.userId = decoded.id;
                    
                    // Update user status
                    const account = await db.Account.findByPk(socket.userId);
                    if (account) {
                        account.isOnline = true;
                        account.lastActive = new Date();
                        await account.save();
                    }
                    
                    return next();
                } catch (err) {
                    return next(new Error('Authentication error: Invalid token'));
                }
            } catch (error) {
                return next(new Error('Authentication error'));
            }
        });

        io.on('connection', async (socket) => {
            const userId = socket.userId;
            console.log(`User connected: ${userId}`);
            
            // Store connection mapping
            connectedUsers.set(userId, socket.id);
            
            // Broadcast user's online status
            broadcastUserStatus(userId, true);
            
            // Handle heartbeat to keep user online
            socket.on('heartbeat', async () => {
                try {
                    const account = await db.Account.findByPk(userId);
                    if (account) {
                        account.lastActive = new Date();
                        await account.save();
                    }
                } catch (error) {
                    console.error('Error updating heartbeat:', error);
                }
            });
            
            // Handle disconnect
            socket.on('disconnect', async () => {
                console.log(`User disconnected: ${userId}`);
                connectedUsers.delete(userId);
                
                try {
                    const account = await db.Account.findByPk(userId);
                    if (account) {
                        account.isOnline = false;
                        account.lastActive = new Date();
                        await account.save();
                    }
                    
                    // Broadcast user's offline status
                    broadcastUserStatus(userId, false);
                } catch (error) {
                    console.error('Error updating user status on disconnect:', error);
                }
            });
        });
        
        console.log('Socket.IO server initialized');
        return io;
    },
    
    // Get the IO instance
    getIO: () => {
        if (!io) {
            throw new Error('Socket.IO not initialized!');
        }
        return io;
    },
    
    // Broadcast online users to all clients
    broadcastOnlineUsers: async () => {
        try {
            const accounts = await db.Account.findAll({
                attributes: ['id', 'title', 'firstName', 'lastName', 'email', 'role', 'isOnline', 'lastActive', 'status', 'created']
            });
            
            io.emit('online-users-update', accounts);
        } catch (error) {
            console.error('Error broadcasting online users:', error);
        }
    },
    
    // Update user's online status in real-time
    updateUserStatus: async (userId, isOnline) => {
        try {
            const account = await db.Account.findByPk(userId);
            if (account) {
                account.isOnline = isOnline;
                account.lastActive = new Date();
                await account.save();
                
                broadcastUserStatus(userId, isOnline);
            }
        } catch (error) {
            console.error('Error updating user status:', error);
        }
    }
};

// Helper function to broadcast individual user status
function broadcastUserStatus(userId, isOnline) {
    io.emit('user-status-change', { userId, isOnline });
} 