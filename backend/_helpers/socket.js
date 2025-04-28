const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const config = require('config.json');
const db = require('./db');

let io;
const connectedUsers = new Map(); // Map of userId -> socketId

module.exports = {
    init: (server) => {
        io = new Server(server, {
            cors: {
                origin: process.env.NODE_ENV === 'production' 
                    ? process.env.FRONTEND_URL 
                    : 'http://localhost:4200',
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
                    const decoded = jwt.verify(token, config.secret);
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