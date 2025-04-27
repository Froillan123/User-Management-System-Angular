const config = require('config.json');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require("crypto");
const { Op } = require('sequelize');
const sendEmail = require('../_helpers/send_email');
const db = require('../_helpers/db');
const Role = require('../_helpers/role');

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
    delete: _delete
};

async function authenticate({ email, password, ipAddress }) {
    try {
        // Find account by email
        const account = await db.Account.scope('withHash').findOne({ where: { email } });

        // Check if account exists
        if (!account) {
            console.error(`Authentication failed: Email not found - ${email}`);
            throw new Error('Email not found');
        }

        // Check if email is verified
        if (!account.isVerified) {
            console.error(`Authentication failed: Email not verified - ${email}`);
            throw new Error('Email not verified');
        }

        // Check if account is active
        if (account.status !== 'Active') {
            console.error(`Authentication failed: Account inactive - ${email} (Status: ${account.status})`);
            throw new Error('Account is inactive');
        }

        // Check password
        const isPasswordValid = await bcrypt.compare(password, account.passwordHash);
        if (!isPasswordValid) {
            console.error(`Authentication failed: Incorrect password - ${email}`);
            throw new Error('Password is incorrect');
        }

        // Generate tokens
        const jwtToken = generateJwtToken(account);
        const refreshToken = generateRefreshToken(account, ipAddress);

        // Save refresh token to database
        await refreshToken.save();

        console.log(`Authentication successful: ${email} (ID: ${account.id})`);

        // Return account details and tokens
        return {
            ...basicDetails(account),
            jwtToken,
            refreshToken: refreshToken.token
        };
    } catch (error) {
        console.error('Authentication error:', error.message || error);
        throw error.message || 'Authentication failed';
    }
}

async function refreshToken({ token, ipAddress }) {
    try {
        if (!token) {
            throw new Error('Token is required');
        }

        // Log refresh attempt
        console.log(`Attempting to refresh token: ${token.substring(0, 10)}...`);

        const refreshToken = await db.RefreshToken.findOne({ 
            where: { token },
            include: [{ model: db.Account }]
        });

        if (!refreshToken) {
            console.error('Refresh token not found in database');
            throw new Error('Invalid token');
        }

        // Access account directly if it was included, or fetch it if needed
        const account = refreshToken.Account || await refreshToken.getAccount();
        if (!account) {
            console.error('Account not found for refresh token');
            throw new Error('Account not found');
        }

        // Check if account is active
        if (account.status !== 'Active') {
            console.error(`Account status is not active: ${account.status}`);
            throw new Error('Account is not active');
        }

        // Check if token is expired
        if (refreshToken.expires < new Date()) {
            console.error('Refresh token has expired');
            throw new Error('Token has expired');
        }

        // Check if token is revoked
        if (refreshToken.revoked) {
            console.error('Refresh token has been revoked');
            throw new Error('Token has been revoked');
        }

        // Generate new refresh token
        const newRefreshToken = generateRefreshToken(account, ipAddress);
        
        // Revoke old refresh token
        refreshToken.revoked = Date.now();
        refreshToken.revokedByIp = ipAddress;
        refreshToken.replacedByToken = newRefreshToken.token;
        
        // Save changes
        await refreshToken.save();
        await newRefreshToken.save();

        // Generate new JWT token
        const jwtToken = generateJwtToken(account);

        console.log(`Successfully refreshed token for account ID: ${account.id}`);
        
        // Return new tokens and account details
        return {
            ...basicDetails(account),
            jwtToken,
            refreshToken: newRefreshToken.token
        };
    } catch (error) {
        console.error('Refresh token error:', error.message || error);
        throw error.message || 'Invalid token';
    }
}

async function revokeToken({ token, ipAddress }) {
    try {
        if (!token) {
            throw 'Token is required';
        }

        const refreshToken = await getRefreshToken(token);
        if (!refreshToken) {
            throw 'Invalid token';
        }

        refreshToken.revoked = Date.now();
        refreshToken.revokedByIp = ipAddress;
        await refreshToken.save();
    } catch (error) {
        console.error('Revoke token error:', error);
        throw 'Invalid token';
    }
}

async function register(params, origin) {
    if (await db.Account.findOne({ where: { email: params.email } })) {
        return await sendAlreadyRegisteredEmail(params.email, origin);
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
    const refreshToken = await db.RefreshToken.findOne({ where: { token } });
    if (!refreshToken || !refreshToken.isActive) throw 'Invalid token';
    return refreshToken;
}

async function hash(password) {
    return await bcrypt.hash(password, 10);
}

function generateJwtToken(account) {
    return jwt.sign(
        {
            sub: account.id,
            id: account.id,
            role: account.role,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + (15 * 60) // 15 minutes
        },
        config.secret
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
    const { id, title, firstName, lastName, email, role, status, created, updated, isVerified } = account;
    return { id, title, firstName, lastName, email, role, status, created, updated, isVerified };
}

async function sendVerificationEmail(account, origin) {
    let message;
    if (origin) {
        const verifyUrl = `${origin}/account/verify-email?token=${account.verificationToken}`;
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
    } else {
        message = `
            <div style="padding: 20px; font-family: Arial, sans-serif;">
                <p>Hello ${account.firstName},</p>
                <p>Thank you for registering with User-Management!</p>
                <p>Please use the below token to verify your email address with the <code>/account/verify-email</code> api route:</p>
                <p style="background-color: #f5f5f5; padding: 10px; border-radius: 4px; font-family: monospace;">${account.verificationToken}</p>
                <p>Best regards,<br>The User-Management Team</p>
            </div>
        `;
    }
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
    if (origin) {
        message = `
            <div style="padding: 20px; font-family: Arial, sans-serif;">
                <p>Hello there,</p>
                <p>Someone (hopefully you) has attempted to register a new account using this email address.</p>
                <p>However, this email address is already registered in our system.</p>
                <p>If you've forgotten your password, you can reset it by clicking the button below:</p>
                <p style="margin: 25px 0;">
                    <a href="${origin}/account/forgot-password" style="background-color: #3498db; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block;">Reset Password</a>
                </p>
                <p>If you did not attempt to register, please ignore this email or contact support if you have concerns.</p>
                <p>Best regards,<br>The User-Management Team</p>
            </div>
        `;
    } else {
        message = `
            <div style="padding: 20px; font-family: Arial, sans-serif;">
                <p>Hello there,</p>
                <p>Someone (hopefully you) has attempted to register a new account using this email address.</p>
                <p>However, this email address is already registered in our system.</p>
                <p>If you've forgotten your password, you can reset it via the <code>/account/forgot-password</code> api route.</p>
                <p>Best regards,<br>The User-Management Team</p>
            </div>
        `;
    }
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
    if (origin) {
        const resetUrl = `${origin}/account/reset-password?token=${account.resetToken}`;
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
    } else {
        message = `
            <div style="padding: 20px; font-family: Arial, sans-serif;">
                <p>Hello ${account.firstName},</p>
                <p>You recently requested to reset your password for your User-Management account.</p>
                <p>Please use the below security token to reset your password:</p>
                <p style="background-color: #f5f5f5; padding: 10px; border-radius: 4px; font-family: monospace;">${account.resetToken}</p>
                <p>This token is only valid for the next 24 hours.</p>
                <p>If you did not request a password reset, please ignore this email.</p>
                <p>Best regards,<br>The User-Management Team</p>
            </div>
        `;
    }
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