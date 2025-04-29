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
    let message;
    // Default verification URL base
    const baseUrl = origin || 'https://user-management-system-angular-tm8z.vercel.app';
    
    // Check which origin to use
    let verifyUrl;
    if (origin) {
        // Use provided origin
        verifyUrl = `${origin}/account/verify-email?token=${account.verificationToken}`;
    } else if (process.env.FRONTEND_URL) {
        // Use environment variable
        verifyUrl = `${process.env.FRONTEND_URL}/account/verify-email?token=${account.verificationToken}`;
    } else {
        // Use default Vercel URL
        verifyUrl = `https://user-management-system-angular-tm8z.vercel.app/account/verify-email?token=${account.verificationToken}`;
    }
    
    message = `
        <div style="padding: 20px; font-family: Arial, sans-serif;">
            <p>Hello ${account.firstName},</p>
            <p>Thank you for registering with User-Management! To complete your registration, please verify your email address by clicking the button below:</p>
            <p style="margin: 25px 0;">
                <a href="${verifyUrl}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block;">Verify Email Address</a>
            </p>
            <p>If the button above doesn't work, you can also click on the link below or copy it into your browser:</p>
            <p><a href="${verifyUrl}">${verifyUrl}</a></p>
            <p>This link will expire in 24 hours.</p>
            <p>Best regards,<br>The User-Management Team</p>
        </div>
    `;

    await sendEmail({
        to: account.email,
        subject: 'User-Management - Verify Your Email Address',
        html: `
            <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border: 1px solid #dddddd; border-radius: 8px; overflow: hidden;">
                <div style="background-color: #2c3e50; padding: 20px; text-align: center;">
                    <h2 style="color: #ffffff; margin: 0;">User-Management</h2>
                </div>
                ${message}
                <div style="background-color: #f5f5f5; padding: 15px; text-align: center; font-size: 12px; color: #666666;">
                    <p>This is an automated email, please do not reply to this message.</p>
                    <p>&copy; ${new Date().getFullYear()} User-Management. All rights reserved.</p>
                </div>
            </div>
        `
    });
}

async function sendAlreadyRegisteredEmail(email, origin) {
    let message;
    // Determine the correct origin for the forgot password link
    let forgotPasswordUrl;
    if (origin) {
        // Use provided origin
        forgotPasswordUrl = `${origin}/account/forgot-password`;
    } else if (process.env.FRONTEND_URL) {
        // Use environment variable
        forgotPasswordUrl = `${process.env.FRONTEND_URL}/account/forgot-password`;
    } else {
        // Use default Vercel URL
        forgotPasswordUrl = `https://user-management-system-angular-tm8z.vercel.app/account/forgot-password`;
    }
    
    message = `
        <div style="padding: 20px; font-family: Arial, sans-serif;">
            <p>Hello there,</p>
            <p>Someone (hopefully you) has attempted to register a new account using this email address.</p>
            <p>However, this email address is already registered in our system.</p>
            <p>If you've forgotten your password, you can reset it by clicking the button below:</p>
            <p style="margin: 25px 0;">
                <a href="${forgotPasswordUrl}" style="background-color: #3498db; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block;">Reset Password</a>
            </p>
            <p>If you did not attempt to register, please ignore this email or contact support if you have concerns.</p>
            <p>Best regards,<br>The User-Management Team</p>
        </div>
    `;

    await sendEmail({
        to: email,
        subject: 'User-Management - Email Already Registered',
        html: `
            <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border: 1px solid #dddddd; border-radius: 8px; overflow: hidden;">
                <div style="background-color: #2c3e50; padding: 20px; text-align: center;">
                    <h2 style="color: #ffffff; margin: 0;">User-Management</h2>
                </div>
                ${message}
                <div style="background-color: #f5f5f5; padding: 15px; text-align: center; font-size: 12px; color: #666666;">
                    <p>This is an automated email, please do not reply to this message.</p>
                    <p>&copy; ${new Date().getFullYear()} User-Management. All rights reserved.</p>
                </div>
            </div>
        `
    });
}

async function sendPasswordResetEmail(account, origin) {
    let message;
    // Check which origin to use
    let resetUrl;
    if (origin) {
        // Use provided origin
        resetUrl = `${origin}/account/reset-password?token=${account.resetToken}`;
    } else if (process.env.FRONTEND_URL) {
        // Use environment variable
        resetUrl = `${process.env.FRONTEND_URL}/account/reset-password?token=${account.resetToken}`;
    } else {
        // Use default Vercel URL
        resetUrl = `https://user-management-system-angular-tm8z.vercel.app/account/reset-password?token=${account.resetToken}`;
    }
    
    message = `
        <div style="padding: 20px; font-family: Arial, sans-serif;">
            <p>Hello ${account.firstName},</p>
            <p>You recently requested to reset your password for your User-Management account.</p>
            <p>To secure your account, please use the secure link below to create a new password:</p>
            <table role="presentation" border="0" cellpadding="0" cellspacing="0" style="margin: 30px auto;">
                <tr>
                    <td align="center" style="border-radius: 4px;" bgcolor="#4285f4">
                        <a href="${resetUrl}" target="_blank" style="border: solid 1px #4285f4; border-radius: 5px; box-sizing: border-box; cursor: pointer; display: inline-block; font-size: 14px; font-weight: bold; margin: 0; padding: 12px 25px; text-decoration: none; text-transform: capitalize; background-color: #4285f4; border-color: #4285f4; color: #ffffff;">Reset Password Securely</a>
                    </td>
                </tr>
            </table>
            <p>For security reasons, this link will expire in 24 hours.</p>
            <p>If you didn't request this password change, you can ignore this message and your password will remain the same.</p>
            <p>For account security, please:</p>
            <ul>
                <li>Never share your password with anyone</li>
                <li>Create a unique password you don't use for other websites</li>
                <li>Include a mix of letters, numbers, and symbols in your password</li>
            </ul>
            <p>Best regards,<br>The User-Management Team</p>
            <p style="font-size: 12px; color: #777777; margin-top: 30px;">
                Note: This is an automated message sent to ${account.email} in response to a password reset request for your User-Management account.
                If you're concerned about the authenticity of this message, please access the User-Management site directly instead of clicking any links.
            </p>
        </div>
    `;

    await sendEmail({
        to: account.email,
        subject: 'Security Alert: Password Reset Request for User-Management Account',
        html: `
            <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border: 1px solid #dddddd; border-radius: 8px; overflow: hidden;">
                <div style="background-color: #2c3e50; padding: 20px; text-align: center;">
                    <h2 style="color: #ffffff; margin: 0;">User-Management Security</h2>
                </div>
                ${message}
                <div style="background-color: #f5f5f5; padding: 15px; text-align: center; font-size: 12px; color: #666666;">
                    <p>This is an automated security notification from User-Management.</p>
                    <p>Please do not reply to this message as the mailbox is not monitored.</p>
                    <p>&copy; ${new Date().getFullYear()} User-Management. All rights reserved.</p>
                </div>
            </div>
        `
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