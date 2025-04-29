const express = require('express');
const router = express.Router();
const Joi = require('joi');
const { Op } = require('sequelize');
const validateRequest = require('../_middleware/validate_request');
const authorize = require('../_middleware/authorize');
const accountService = require('./account.service');
const socketModule = require('../_helpers/socket');
const db = require('../_helpers/db');

// Routes
router.get('/user-stats', authorize(), getUserStats);
router.get('/online-users', authorize(), getOnlineUsers);

module.exports = router;

function getUserStats(req, res, next) {
    accountService.getAllAccounts()
        .then(accounts => {
            // Calculate statistics
            const totalUsers = accounts.length;
            const activeUsers = accounts.filter(x => x.status === 'Active').length;
            const verifiedUsers = accounts.filter(x => x.isVerified).length;
            const onlineUsers = accounts.filter(x => x.isOnline).length;
            
            // For refresh tokens, we need to get them from the refresh-token model
            db.RefreshToken.count()
                .then(refreshTokenCount => {
                    // Return stats with monthly data
                    const stats = {
                        totalUsers,
                        activeUsers,
                        verifiedUsers,
                        onlineUsers,
                        refreshTokenCount,
                        monthlyData: generateMonthlyData(accounts)
                    };
                    
                    res.json(stats);
                    
                    // Broadcast stats via WebSocket
                    try {
                        const io = socketModule.getIO();
                        io.emit('user-stats-update', stats);
                    } catch (error) {
                        console.error('WebSocket broadcasting error:', error);
                    }
                })
                .catch(next);
        })
        .catch(next);
}

function getOnlineUsers(req, res, next) {
    // Update online status first
    updateOnlineStatuses()
        .then(() => {
            // Get all accounts
            accountService.getAllAccounts()
                .then(accounts => {
                    // Map accounts to include online status
                    const usersWithStatus = accounts.map(account => ({
                        id: account.id,
                        title: account.title,
                        firstName: account.firstName,
                        lastName: account.lastName,
                        email: account.email,
                        role: account.role,
                        created: account.created,
                        status: account.status,
                        isVerified: account.isVerified,
                        isOnline: account.isOnline,
                        lastActive: account.lastActive
                    }));
                    
                    // Return the users
                    res.json(usersWithStatus);
                    
                    // Broadcast online users via WebSocket
                    try {
                        const io = socketModule.getIO();
                        io.emit('online-users-update', usersWithStatus);
                    } catch (error) {
                        console.error('WebSocket broadcasting error:', error);
                    }
                })
                .catch(next);
        })
        .catch(next);
}

// Helper function to update online status
async function updateOnlineStatuses() {
    try {
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
        
        // Find all accounts with lastActive time
        const accounts = await db.Account.findAll({
            where: {
                lastActive: {
                    [Op.ne]: null
                }
            }
        });
        
        // Update each account's online status
        const statusChanges = [];
        
        for (const account of accounts) {
            const wasOnline = account.isOnline;
            const isOnline = account.lastActive && new Date(account.lastActive) > fiveMinutesAgo;
            
            if (wasOnline !== isOnline) {
                account.isOnline = isOnline;
                await account.save();
                
                statusChanges.push({
                    userId: account.id,
                    isOnline
                });
            }
        }
        
        // Broadcast status changes via WebSocket
        if (statusChanges.length > 0) {
            try {
                const io = socketModule.getIO();
                statusChanges.forEach(change => {
                    io.emit('user-status-change', change);
                });
            } catch (error) {
                console.error('WebSocket broadcasting error:', error);
            }
        }
        
        return Promise.resolve();
    } catch (error) {
        return Promise.reject(error);
    }
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