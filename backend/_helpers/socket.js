const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const config = require('../config.json');
const db = require('./db');

// Determine environment
const env = process.env.NODE_ENV === 'production' ? 'production' : 'development';
const envConfig = config[env];

let io;
const connectedUsers = new Map(); // Map of userId -> socketId
const userHeartbeats = new Map(); // Map of userId -> last heartbeat timestamp

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
            },
            pingTimeout: 60000,
            pingInterval: 25000
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
            
            // Store connection mapping and heartbeat
            connectedUsers.set(userId, socket.id);
            userHeartbeats.set(userId, new Date());
            
            // Broadcast user's online status
            broadcastUserStatus(userId, true);
            
            // Handle get-online-users request
            socket.on('get-online-users', async () => {
                try {
                    const accounts = await db.Account.findAll({
                        attributes: ['id', 'title', 'firstName', 'lastName', 'email', 'role', 'isOnline', 'lastActive', 'status', 'created']
                    });
                    
                    // Filter out users who haven't sent a heartbeat in the last 5 minutes
                    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
                    const activeUsers = accounts.filter(account => {
                        const lastHeartbeat = userHeartbeats.get(account.id);
                        return lastHeartbeat && new Date(lastHeartbeat) > fiveMinutesAgo;
                    });
                    
                    socket.emit('online-users-update', activeUsers);
                } catch (error) {
                    console.error('Error getting online users:', error);
                }
            });
            
            // Handle get-user-stats request
            socket.on('get-user-stats', async () => {
                try {
                    const accounts = await db.Account.findAll();
                    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
                    
                    // Count only users with recent heartbeats
                    const onlineUsers = accounts.filter(account => {
                        const lastHeartbeat = userHeartbeats.get(account.id);
                        return lastHeartbeat && new Date(lastHeartbeat) > fiveMinutesAgo;
                    }).length;
                    
                    const stats = {
                        totalUsers: accounts.length,
                        activeUsers: accounts.filter(x => x.status === 'Active').length,
                        verifiedUsers: accounts.filter(x => x.isVerified).length,
                        onlineUsers,
                        monthlyData: generateMonthlyData(accounts)
                    };
                    socket.emit('user-stats-update', stats);
                } catch (error) {
                    console.error('Error getting user stats:', error);
                }
            });
            
            // Handle heartbeat to keep user online
            socket.on('heartbeat', async () => {
                try {
                    const account = await db.Account.findByPk(userId);
                    if (account) {
                        account.lastActive = new Date();
                        await account.save();
                        userHeartbeats.set(userId, new Date());
                    }
                } catch (error) {
                    console.error('Error updating heartbeat:', error);
                }
            });
            
            // Handle disconnect
            socket.on('disconnect', async () => {
                console.log(`User disconnected: ${userId}`);
                connectedUsers.delete(userId);
                userHeartbeats.delete(userId);
                
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
        
        // Start cleanup interval to remove stale heartbeats
        setInterval(() => {
            const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
            for (const [userId, lastHeartbeat] of userHeartbeats.entries()) {
                if (new Date(lastHeartbeat) <= fiveMinutesAgo) {
                    userHeartbeats.delete(userId);
                    broadcastUserStatus(userId, false);
                }
            }
        }, 60000); // Check every minute
        
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
            
            // Filter out users who haven't sent a heartbeat in the last 5 minutes
            const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
            const activeUsers = accounts.filter(account => {
                const lastHeartbeat = userHeartbeats.get(account.id);
                return lastHeartbeat && new Date(lastHeartbeat) > fiveMinutesAgo;
            });
            
            io.emit('online-users-update', activeUsers);
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
                
                if (isOnline) {
                    userHeartbeats.set(userId, new Date());
                } else {
                    userHeartbeats.delete(userId);
                }
                
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

// Helper function to generate monthly registration data
function generateMonthlyData(accounts) {
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
        if (account.created) {
            const createdDate = new Date(account.created);
            const monthIndex = createdDate.getMonth();
            monthlyCounts[monthIndex].count++;
        }
    });
    
    // Mark current month
    monthlyCounts[currentMonth].isCurrent = true;
    
    return monthlyCounts;
} 