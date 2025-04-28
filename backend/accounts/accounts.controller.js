const express = require('express');
const router = express.Router();
const Joi = require('joi');
const validateRequest = require('../_middleware/validate_request');
const authorize = require('../_middleware/authorize');
const Role = require('../_helpers/role');
const accountService = require('./account.service');

// routes
router.post('/authenticate', authenticateSchema, authenticate);
router.post('/refresh-token', refreshToken);
router.post('/revoke-token', revokeTokenSchema, revokeToken);
router.post('/register', registerSchema, register);
router.post('/verify-email', verifyEmailSchema, verifyEmail);
router.post('/forgot-password', forgotPasswordSchema, forgotPassword);
router.post('/validate-reset-token', validateResetTokenSchema, validateResetToken);
router.post('/reset-password', resetPasswordSchema, resetPassword);
router.get('/', authorize(Role.Admin), getAll);
router.get('/:id', authorize(), getById);
router.post('/', authorize(Role.Admin), createSchema, create);
router.put('/:id', authorize(), updateSchema, update);
router.delete('/:id', authorize(), _delete);

module.exports = router;

function authenticateSchema(req, res, next) {
    const schema = Joi.object({
        email: Joi.string().required(),
        password: Joi.string().required()
    });
    validateRequest(req, next, schema);
}

function authenticate(req, res, next) {
    const { email, password } = req.body;
    const ipAddress = req.ip;
    
    // Add more detailed logging
    console.log(`Authentication attempt for email: ${email}, IP: ${ipAddress}`);
    
    accountService.authenticate({ email, password, ipAddress })
        .then(({ refreshToken, ...account }) => {
            // Log successful authentication
            console.log(`Authentication successful for user ID: ${account.id}`);
            
            // Set the refresh token cookie
            setTokenCookie(res, refreshToken);
            
            // Include user ID in the response
            res.json({
                ...account,
                id: account.id
            });
        })
        .catch(error => {
            // Log authentication failure
            console.error(`Authentication failed: ${error.message}`);
            next(error);
        });
}

function refreshToken(req, res, next) {
    // Accept token from cookies or request body
    const token = req.cookies.refreshToken || req.body.refreshToken;
    const ipAddress = req.ip;
    
    // Log refresh token attempt
    console.log(`Refresh token attempt, IP: ${ipAddress}`);
    
    if (!token) {
        return res.status(400).json({ message: 'Refresh token is required' });
    }

    accountService.refreshToken({ token, ipAddress })
        .then(({ refreshToken, ...account }) => {
            // Log successful token refresh
            console.log(`Token refresh successful for user ID: ${account.id}`);
            
            // Set the refresh token cookie
            setTokenCookie(res, refreshToken);
            
            res.json(account);
        })
        .catch(error => {
            // Log token refresh failure
            console.error(`Token refresh failed: ${error.message}`);
            next(error);
        });
}

function revokeTokenSchema(req, res, next) {
    const schema = Joi.object({
        token: Joi.string().empty('')
    });
    validateRequest(req, next, schema);
}

function revokeToken(req, res, next) {
    // accept token from request body or cookie
    const token = req.body.token || req.cookies.refreshToken;
    const ipAddress = req.ip;

    if (!token) return res.status(400).json({ message: 'Token is required' });

    accountService.revokeToken({ token, ipAddress })
        .then(() => res.json({ message: 'Token revoked' }))
        .catch(next);
}

function registerSchema(req, res, next) {
    const schema = Joi.object({
        title: Joi.string().required(),
        firstName: Joi.string().required(),
        lastName: Joi.string().required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(6).required(),
        confirmPassword: Joi.string().valid(Joi.ref('password')).required(),
        acceptTerms: Joi.boolean().valid(true).required()
    });
    validateRequest(req, next, schema);
}

function register(req, res, next) {
    accountService.register(req.body, req.get('origin'))
        .then(result => res.json(result)) // ✅ Send full result including verificationToken
        .catch(next);
}

function verifyEmailSchema(req, res, next) {
    const schema = Joi.object({
        token: Joi.string().required()
    });
    validateRequest(req, next, schema);
}

function verifyEmail(req, res, next) {
    accountService.verifyEmail(req.body)
        .then(() => res.json({ message: 'Verification successful, you can now login' }))
        .catch(next);
}

function forgotPasswordSchema(req, res, next) {
    const schema = Joi.object({
        email: Joi.string().email().required()
    });
    validateRequest(req, next, schema);
}

function forgotPassword(req, res, next) {
    accountService.forgotPassword(req.body, req.get('origin'))
        .then(() => res.json({ message: 'Please check your email for password reset instructions' }))
        .catch(next);
}

function validateResetTokenSchema(req, res, next) {
    const schema = Joi.object({
        token: Joi.string().required()
    });
    validateRequest(req, next, schema);
}

function validateResetToken(req, res, next) {
    accountService.validateResetToken(req.body)
        .then(() => res.json({ message: 'Token is valid' }))
        .catch(next);
}

function resetPasswordSchema(req, res, next) {
    const schema = Joi.object({
        token: Joi.string().required(),
        password: Joi.string().min(6).required(),
        confirmPassword: Joi.string().valid(Joi.ref('password')).required()
    });
    validateRequest(req, next, schema);
}

function resetPassword(req, res, next) {
    accountService.resetPassword(req.body)
        .then(() => res.json({ message: 'Password reset successful, you can now login' }))
        .catch(next);
}

function getAll(req, res, next) {
    console.log('GET /accounts - Fetching all accounts');
    console.log('User:', req.user);

    accountService.getAll()
        .then(accounts => {
            console.log(`Successfully retrieved ${accounts.length} accounts`);
            res.json(accounts);
        })
        .catch(error => {
            console.error('Error fetching accounts:', error);
            next(error);
        });
}

function getById(req, res, next) {
    const id = req.params.id;
    console.log(`GET /accounts/${id} - Fetching account by ID`);
    console.log('Authenticated user:', req.user);
    
    // users can get their own account and admins can get any account
    if (Number(id) !== req.user.id && req.user.role !== Role.Admin) {
        console.error(`Unauthorized access - User ${req.user.id} attempted to access account ${id}`);
        return res.status(401).json({ message: 'Unauthorized' });
    }

    accountService.getById(id)
        .then(account => {
            if (account) {
                console.log(`Successfully retrieved account ${id}`);
                res.json(account);
            } else {
                console.error(`Account ${id} not found`);
                res.status(404).json({ message: 'Account not found' });
            }
        })
        .catch(error => {
            console.error(`Error fetching account ${id}:`, error);
            next(error);
        });
}

function createSchema(req, res, next) {
    const schema = Joi.object({
        title: Joi.string().required(),
        firstName: Joi.string().required(),
        lastName: Joi.string().required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(6).required(),
        confirmPassword: Joi.string().valid(Joi.ref('password')).required(),
        role: Joi.string().valid(Role.Admin, Role.User).required()
    });
    validateRequest(req, next, schema);
}

function create(req, res, next) {
    accountService.create(req.body)
        .then(account => res.json(account))
        .catch(next);
}

function updateSchema(req, res, next) {
    const schemaRules = {
        title: Joi.string().empty(''),
        firstName: Joi.string().empty(''),
        lastName: Joi.string().empty(''),
        email: Joi.string().email().empty(''),
        password: Joi.string().min(6).empty(''),
        confirmPassword: Joi.string().valid(Joi.ref('password')).empty('')
    };

    // only admins can update role and status
    if (req.user.role === Role.Admin) {
        schemaRules.role = Joi.string().valid(Role.Admin, Role.User).empty('');
        schemaRules.status = Joi.string().valid('Active', 'Inactive').empty('');
    }

    const schema = Joi.object(schemaRules).with('password', 'confirmPassword');
    validateRequest(req, next, schema);
}

function update(req, res, next) {
    const id = req.params.id;
    console.log(`PUT /accounts/${id} - Updating account`);
    console.log('Request body:', req.body);
    console.log('Authenticated user:', req.user);
    
    // users can update their own account and admins can update any account
    if (Number(id) !== req.user.id && req.user.role !== Role.Admin) {
        console.error(`Unauthorized update - User ${req.user.id} attempted to update account ${id}`);
        return res.status(401).json({ message: 'Unauthorized' });
    }

    accountService.update(id, req.body)
        .then(account => {
            console.log(`Successfully updated account ${id}`);
            res.json(account);
        })
        .catch(error => {
            console.error(`Error updating account ${id}:`, error);
            next(error);
        });
}

function _delete(req, res, next) {
    // users can delete their own account and admins can delete any account
    if (Number(req.params.id) !== req.user.id && req.user.role !== Role.Admin) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    accountService.delete(req.params.id)
        .then(() => res.json({ message: 'Account deleted successfully' }))
        .catch(next);
}

// helper functions

function setTokenCookie(res, token) {
    // Create cookie options with proper security settings
    const cookieOptions = {
        httpOnly: true,
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        sameSite: 'none',
        secure: process.env.NODE_ENV === 'production'
    };
    
    console.log(`Setting refresh token cookie with options: ${JSON.stringify({
        secure: cookieOptions.secure,
        sameSite: cookieOptions.sameSite,
        expiresIn: '7 days'
    })}`);
    
    res.cookie('refreshToken', token, cookieOptions);
}
