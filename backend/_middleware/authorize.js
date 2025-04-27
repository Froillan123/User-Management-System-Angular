const { expressjwt: jwt } = require("express-jwt");
const secret = process.env.JWT_SECRET || 'your-super-secret-jwt-key';
const db = require('../_helpers/db');

module.exports = authorize;

function authorize(roles = []) {
    if (typeof roles === 'string') {
        roles = [roles];
    }

    const jwtOptions = {
        secret,
        algorithms: ['HS256'],
        credentialsRequired: true,
        requestProperty: 'auth',
        getToken: function fromHeaderOrQuerystring(req) {
            // Log all available headers for debugging
            console.log('Headers:', JSON.stringify(req.headers));
            
            // Check Authorization header first
            if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
                const token = req.headers.authorization.split(' ')[1];
                console.log(`Bearer token found: ${token.substring(0, 20)}...`);
                return token;
            } 
            
            // Check query parameter
            if (req.query && req.query.token) {
                console.log(`Query token found: ${req.query.token.substring(0, 20)}...`);
                return req.query.token;
            } 
            
            // Check cookies
            if (req.cookies && req.cookies.refreshToken) {
                console.log(`Cookie token found: ${req.cookies.refreshToken.substring(0, 20)}...`);
                return req.cookies.refreshToken;
            }
            
            console.log('No token found in request');
            return null;
        }
    };

    return [
        // JWT middleware with proper configuration
        jwt(jwtOptions).unless({ 
            path: [
                // Public routes that don't require authentication
                '/accounts/authenticate',
                '/accounts/refresh-token',
                '/accounts/register',
                '/accounts/verify-email',
                '/accounts/forgot-password',
                '/accounts/validate-reset-token',
                '/accounts/reset-password'
            ]
        }),

        // Authorization middleware
        async (req, res, next) => {
            // Skip authorization for routes that don't require authentication
            const publicRoutes = [
                '/accounts/authenticate',
                '/accounts/refresh-token',
                '/accounts/register',
                '/accounts/verify-email',
                '/accounts/forgot-password',
                '/accounts/validate-reset-token',
                '/accounts/reset-password'
            ];
            
            if (publicRoutes.some(route => req.path.includes(route))) {
                console.log(`Public route accessed: ${req.path}`);
                return next();
            }

            try {
                console.log(`Authorization check for path: ${req.path}`);
                console.log('Auth object:', JSON.stringify(req.auth || 'No auth object'));
                
                // Check if token was properly verified
                if (!req.auth || !req.auth.id) {
                    console.error('Invalid token - missing auth or id');
                    return res.status(401).json({ message: 'Invalid token' });
                }

                // Get account from database
                const account = await db.Account.findByPk(req.auth.id);
                if (!account) {
                    console.error(`Account not found for ID: ${req.auth.id}`);
                    return res.status(401).json({ message: 'Account not found' });
                }

                // Log successful account retrieval
                console.log(`Account found: ${account.email} (ID: ${account.id}, Role: ${account.role})`);

                // Check if account is active
                if (account.status !== 'Active') {
                    console.error(`Account is inactive: ${account.status}`);
                    return res.status(401).json({ message: 'Account is inactive' });
                }
                
                // Check roles if specified
                if (roles.length && !roles.includes(account.role)) {
                    console.error(`Insufficient permissions. Required: ${roles.join(', ')}, Account has: ${account.role}`);
                    return res.status(401).json({ message: 'Insufficient permissions' });
                }

                // Attach user to request
                req.user = {
                    id: account.id,
                    role: account.role,
                    // Add refresh token verification
                    ownsToken: async (token) => {
                        const refreshTokens = await account.getRefreshTokens();
                        return refreshTokens.some(x => x.token === token);
                    }
                };

                console.log(`Authorization successful for user ID: ${account.id}`);
                next();
            } catch (err) {
                console.error('Authorization error:', err);
                return res.status(401).json({ 
                    message: 'Authorization failed',
                    error: err.message || 'Unknown error'
                });
            }
        }
    ];
}