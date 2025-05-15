const config = require('../config.json');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require("crypto");
const { Op } = require('sequelize');
const sendEmail = require('../_helpers/send_email');
const db = require('../_helpers/db');
const Role = require('../_helpers/role');

// Determine environment
const env = process.env.NODE_ENV === 'production' ? 'production' : 'development';
const envConfig = config[env];

// Log configuration
console.log(`Using ${env} environment for account service`);

module.exports = {
    authenticate,
    refreshToken,
    revokeToken,
    register,
    verifyEmail,
    forgotPassword,
    validateResetToken,
    resetPassword,
    getAll,
    getById,
    create,
    update,
    delete: _delete,
    getAllAccounts,
    setOffline
};

async function authenticate({ email, password, ipAddress }) {
    const account = await db.Account.scope('withHash').findOne({ where: { email } });

    if (!account) {
        throw 'Email does not exist';
    }

    if (!account.isVerified) {
        throw 'Email not yet verified';
    }

    if (account.status !== 'Active') {
        throw 'Account is inactive.';
    }

    const isPasswordValid = await bcrypt.compare(password, account.passwordHash);
    if (!isPasswordValid) {
        throw 'Password is incorrect';
    }

    account.isOnline = true;
    account.lastActive = new Date();
    await account.save();

    try {
        const socketModule = require('../_helpers/socket');
        socketModule.updateUserStatus(account.id, true);
    } catch (error) {
        console.error('Error broadcasting online status:', error);
    }

    const jwtToken = generateJwtToken(account);
    const refreshToken = generateRefreshToken(account, ipAddress);

    await refreshToken.save();

    return {
        ...basicDetails(account),
        jwtToken,
        refreshToken: refreshToken.token
    };
}

async function refreshToken({ token, ipAddress }) {
    if (!token) {
        throw 'Refresh token is required';
    }

    try {
        const refreshToken = await getRefreshToken(token);
        const account = await refreshToken.getAccount();

        // Verify account is still active
        if (account.status !== 'Active') {
            throw 'Account is inactive';
        }

        account.isOnline = true;
        account.lastActive = new Date();
        await account.save();

        const newRefreshToken = generateRefreshToken(account, ipAddress);
        refreshToken.revoked = Date.now();
        refreshToken.revokedByIp = ipAddress;
        refreshToken.replacedByToken = newRefreshToken.token;
        
        await refreshToken.save();
        await newRefreshToken.save();

        const jwtToken = generateJwtToken(account);

        return {
            ...basicDetails(account),
            jwtToken,
            refreshToken: newRefreshToken.token
        };
    } catch (error) {
        console.error('Refresh token error:', error);
        throw 'Invalid token';
    }
}

async function revokeToken({ token, ipAddress }) {
    const refreshToken = await getRefreshToken(token);
    
    const account = await refreshToken.getAccount();
    account.isOnline = false;
    account.lastActive = new Date();
    await account.save();
    
    try {
        const socketModule = require('../_helpers/socket');
        socketModule.updateUserStatus(account.id, false);
    } catch (error) {
        console.error('Error broadcasting offline status:', error);
    }
    
    refreshToken.revoked = Date.now();
    refreshToken.revokedByIp = ipAddress;
    await refreshToken.save();
}

async function register(params, origin) {
    if (await db.Account.findOne({ where: { email: params.email } })) {
        await sendAlreadyRegisteredEmail(params.email, origin);
        throw 'Email "' + params.email + '" is already registered';
    }

    const account = new db.Account(params);
    const isFirstAccount = (await db.Account.count()) === 0;
    account.role = isFirstAccount ? Role.Admin : Role.User;
    account.status = isFirstAccount ? 'Active' : 'Inactive';
    account.verificationToken = isFirstAccount ? null : randomTokenString();

    if (isFirstAccount) {
        account.verified = Date.now();
    }

    account.passwordHash = await hash(params.password);
    await account.save();

    try {
        if (!isFirstAccount) {
            await sendVerificationEmail(account, origin);
        }
    } catch (err) {
        console.error("Email sending failed:", err.message);
    }

    return {
        message: isFirstAccount 
            ? 'Registration successful. You can now login.'
            : 'Registration successful, please check your email for verification instructions'
    };
}

async function verifyEmail({ token }) {
    const account = await db.Account.findOne({ where: { verificationToken: token } });
    if (!account) throw 'Verification failed';

    account.verified = Date.now();
    account.verificationToken = null;
    account.status = 'Active';
    await account.save();
}

async function forgotPassword({ email }, origin) {
    const account = await db.Account.findOne({ where: { email } });

    if (!account) return;

    account.resetToken = randomTokenString();
    account.resetTokenExpires = new Date(Date.now() + 24*60*60*1000);
    await account.save();

    await sendPasswordResetEmail(account, origin);
}

async function validateResetToken({ token }) {
    const account = await db.Account.findOne({
        where: {
            resetToken: token,
            resetTokenExpires: { [Op.gt]: Date.now() }
        }
    });

    if (!account) throw 'Invalid token';

    return account;
}

async function resetPassword({ token, password }) {
    const account = await validateResetToken({ token });

    account.passwordHash = await hash(password);
    account.passwordReset = Date.now();
    account.resetToken = null;
    account.resetTokenExpires = null;
    await account.save();
}

async function getAll() {
    const accounts = await db.Account.findAll();
    return accounts.map(x => basicDetails(x));
}

async function getAllAccounts() {
    return await db.Account.findAll();
}

async function getById(id) {
    const account = await getAccount(id);
    return basicDetails(account);
}

async function create(params) {
    if (await db.Account.findOne({ where: { email: params.email } })) {
        throw 'Email "' + params.email + '" is already registered';
    }

    const account = new db.Account(params);
    account.verified = Date.now();
    account.verificationToken = null;
    account.status = params.status || 'Active';
    account.role = params.role || Role.User;
    account.passwordHash = await hash(params.password);
    await account.save();
    return basicDetails(account);
}

async function update(id, params) {
    const account = await getAccount(id);
    if (params.email && account.email !== params.email && await db.Account.findOne({ where: { email: params.email } })) {
        throw 'Email "' + params.email + '" is already taken';
    }

    if (params.password) {
        params.passwordHash = await hash(params.password);
    }

    Object.assign(account, params);
    account.updated = Date.now();
    await account.save();
    return basicDetails(account);
}

async function _delete(id) {
    const account = await getAccount(id);
    await account.destroy();
}

async function getAccount(id) {
    const account = await db.Account.findByPk(id);
    if (!account) throw 'Account not found';
    return account;
}

async function getRefreshToken(token) {
    if (!token || token === 'undefined') {
        console.error('Invalid refresh token: token is undefined or null');
        throw 'Invalid refresh token: token is missing';
    }
    
    try {
        const refreshToken = await db.RefreshToken.findOne({ where: { token } });
        
        if (!refreshToken) {
            console.error(`No refresh token found in database for token: ${token.substring(0, 10)}...`);
            throw 'Invalid token: token not found';
        }
        
        if (!refreshToken.isActive) {
            console.error(`Refresh token is inactive or expired: ${token.substring(0, 10)}...`);
            throw 'Invalid token: token is inactive or expired';
        }
        
        return refreshToken;
    } catch (error) {
        console.error('Error retrieving refresh token:', error);
        throw 'Invalid token';
    }
}

async function hash(password) {
    return await bcrypt.hash(password, 10);
}

function generateJwtToken(account) {
    // Log JWT secret access for debugging
    console.log(`Generating JWT token with secret from ${env} environment`);
    if (!envConfig.secret) {
        console.error('JWT secret is missing or undefined!');
        throw new Error('JWT secret configuration is missing');
    }
    
    return jwt.sign(
        {
            sub: account.id,
            id: account.id,
            role: account.role
        },
        envConfig.secret,
        { expiresIn: '15m' }
    );
}

function generateRefreshToken(account, ipAddress) {
    return new db.RefreshToken({
        accountId: account.id,
        token: randomTokenString(),
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        createdByIp: ipAddress
    });
}

function randomTokenString() {
    return crypto.randomBytes(40).toString('hex');
}

function basicDetails(account) {
    const { id, title, firstName, lastName, email, role, created, updated, status, isVerified, isOnline, lastActive } = account;
    return { id, title, firstName, lastName, email, role, created, updated, status, isVerified, isOnline, lastActive };
}

async function sendVerificationEmail(account, origin) {
    let baseUrl;
    if (origin) {
        baseUrl = origin;
    } else {
        baseUrl = env === 'development' 
            ? 'http://localhost:4200'
            : 'https://user-management-system-angular.vercel.app';
    }
    
    const verifyUrl = `${baseUrl}/account/verify-email?token=${account.verificationToken}`;
    
    const message = `
        <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
            <div style="background: linear-gradient(135deg, #6e8efb, #a777e3); padding: 30px; text-align: center; border-radius: 8px 8px 0 0;">
                <h1 style="color: white; margin: 0;">Welcome to User-Management!</h1>
            </div>
            
            <div style="padding: 30px; background: #ffffff; line-height: 1.6;">
                <p style="font-size: 16px;">Hi ${account.firstName},</p>
                <p style="font-size: 16px;">Thank you for registering with User-Management. We're excited to have you on board!</p>
                
                <div style="text-align: center; margin: 30px 0;">
                    <a href="${verifyUrl}" style="background: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
                        Verify Your Email
                    </a>
                </div>
                
                <p style="font-size: 16px;">Or copy and paste this link into your browser:</p>
                <div style="word-break: break-all; padding: 15px; background: #f5f5f5; border-radius: 4px; margin-bottom: 20px;">
                    <a href="${verifyUrl}" style="color: #3498db; text-decoration: none;">${verifyUrl}</a>
                </div>
                
                <p style="font-size: 16px;">This verification link will expire in 24 hours.</p>
                <p style="font-size: 16px;">If you didn't create an account with us, please ignore this email.</p>
            </div>
            
            <div style="padding: 20px; text-align: center; background: #f9f9f9; border-radius: 0 0 8px 8px; font-size: 14px; color: #666;">
                <p>© ${new Date().getFullYear()} User-Management. All rights reserved.</p>
                <p style="margin-top: 10px;">
                    <a href="#" style="color: #3498db; text-decoration: none; margin: 0 10px;">Help Center</a>
                    <a href="#" style="color: #3498db; text-decoration: none; margin: 0 10px;">Privacy Policy</a>
                    <a href="#" style="color: #3498db; text-decoration: none; margin: 0 10px;">Terms of Service</a>
                </p>
            </div>
        </div>
    `;

    await sendEmail({
        to: account.email,
        subject: 'Please verify your email address',
        html: message
    });
}

async function sendAlreadyRegisteredEmail(email, origin) {
    let baseUrl;
    if (origin) {
        baseUrl = origin;
    } else {
        baseUrl = env === 'development' 
            ? 'http://localhost:4200'
            : 'https://user-management-system-angular.vercel.app';
    }
    
    const forgotPasswordUrl = `${baseUrl}/account/forgot-password`;
    
    const message = `
        <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
            <div style="background: linear-gradient(135deg, #6e8efb, #a777e3); padding: 30px; text-align: center; border-radius: 8px 8px 0 0;">
                <h1 style="color: white; margin: 0;">Account Already Exists</h1>
            </div>
            
            <div style="padding: 30px; background: #ffffff; line-height: 1.6;">
                <p style="font-size: 16px;">Hello,</p>
                <p style="font-size: 16px;">We received a request to register an account with this email address, but it's already registered in our system.</p>
                
                <div style="background: #fff8e1; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0;">
                    <p style="font-size: 16px; margin: 0;">If you've forgotten your password, you can reset it using the link below:</p>
                </div>
                
                <div style="text-align: center; margin: 30px 0;">
                    <a href="${forgotPasswordUrl}" style="background: #3498db; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
                        Reset Your Password
                    </a>
                </div>
                
                <p style="font-size: 16px;">If you didn't attempt to register, no further action is required. Your account is secure.</p>
                <p style="font-size: 16px;">For security reasons, we recommend changing your password regularly and enabling two-factor authentication if available.</p>
            </div>
            
            <div style="padding: 20px; text-align: center; background: #f9f9f9; border-radius: 0 0 8px 8px; font-size: 14px; color: #666;">
                <p>© ${new Date().getFullYear()} User-Management. All rights reserved.</p>
                <p style="margin-top: 10px; font-size: 12px; color: #999;">
                    This is an automated message. Please do not reply to this email.
                </p>
            </div>
        </div>
    `;

    await sendEmail({
        to: email,
        subject: 'Email address already registered',
        html: message
    });
}

async function sendPasswordResetEmail(account, origin) {
    let baseUrl;
    if (origin) {
        baseUrl = origin;
    } else {
        baseUrl = env === 'development' 
            ? 'http://localhost:4200'
            : 'https://user-management-system-angular.vercel.app';
    }
    
    const resetUrl = `${baseUrl}/account/reset-password?token=${account.resetToken}`;
    
    const message = `
        <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
            <div style="background: linear-gradient(135deg, #ff6b6b, #ffa3a3); padding: 30px; text-align: center; border-radius: 8px 8px 0 0;">
                <h1 style="color: white; margin: 0;">Password Reset Request</h1>
            </div>
            
            <div style="padding: 30px; background: #ffffff; line-height: 1.6;">
                <p style="font-size: 16px;">Hi ${account.firstName},</p>
                <p style="font-size: 16px;">We received a request to reset the password for your User-Management account.</p>
                
                <div style="background: #ffebee; border-left: 4px solid #f44336; padding: 15px; margin: 20px 0;">
                    <p style="font-size: 16px; margin: 0; font-weight: bold;">This link will expire in 24 hours.</p>
                </div>
                
                <div style="text-align: center; margin: 30px 0;">
                    <a href="${resetUrl}" style="background: #4285f4; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
                        Reset Password
                    </a>
                </div>
                
                <p style="font-size: 16px;">If you didn't request this password reset, please ignore this email or contact support if you have concerns.</p>
                
                <div style="margin-top: 30px; padding: 15px; background: #f5f5f5; border-radius: 4px;">
                    <h3 style="margin-top: 0; color: #333;">Password Security Tips:</h3>
                    <ul style="padding-left: 20px;">
                        <li style="margin-bottom: 8px;">Use a unique password for each service</li>
                        <li style="margin-bottom: 8px;">Include numbers, symbols, and both uppercase and lowercase letters</li>
                        <li style="margin-bottom: 8px;">Avoid using personal information or common words</li>
                        <li>Consider using a password manager</li>
                    </ul>
                </div>
            </div>
            
            <div style="padding: 20px; text-align: center; background: #f9f9f9; border-radius: 0 0 8px 8px; font-size: 14px; color: #666;">
                <p>© ${new Date().getFullYear()} User-Management. All rights reserved.</p>
                <p style="margin-top: 10px; font-size: 12px; color: #999;">
                    For security reasons, we do not store your password. This link will expire after use.
                </p>
            </div>
        </div>
    `;

    await sendEmail({
        to: account.email,
        subject: 'Password reset instructions',
        html: message
    });
}

async function setOffline(userId) {
    const account = await db.Account.findByPk(userId);
    if (!account) {
        throw 'Account not found';
    }

    account.isOnline = false;
    account.lastActive = new Date();
    await account.save();

    return account;
}