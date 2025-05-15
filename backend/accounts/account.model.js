// Import DataTypes from Sequelize for defining model attributes
const { DataTypes } = require('sequelize');

// Export the model function to be used elsewhere
module.exports = model;

// Main model definition function
function model(sequelize) {
    // Define the attributes (columns) for the account table
    const attributes = {
        email: { type: DataTypes.STRING, allowNull: false }, // Email field, required
        passwordHash: { type: DataTypes.STRING, allowNull: false }, // Hashed password, required
        title: { type: DataTypes.STRING, allowNull: false }, // Title (Mr, Mrs, etc), required
        firstName: { type: DataTypes.STRING, allowNull: false }, // First name, required
        lastName: { type: DataTypes.STRING, allowNull: false }, // Last name, required
        acceptTerms: { type: DataTypes.BOOLEAN }, // Whether terms were accepted
        role: { type: DataTypes.STRING, allowNull: false }, // User role, required
        verificationToken: { type: DataTypes.STRING }, // Token for email verification
        verified: { type: DataTypes.DATE }, // Date when account was verified
        resetToken: { type: DataTypes.STRING }, // Token for password reset
        resetTokenExpires: { type: DataTypes.DATE }, // Expiration date for reset token
        passwordReset: { type: DataTypes.DATE }, // Date when password was last reset
        created: { 
            type: DataTypes.DATE, 
            allowNull: false, 
            defaultValue: DataTypes.NOW // Default to current timestamp
        },
        status: { 
            type: DataTypes.ENUM('Active', 'Inactive'), // Only allow these values
            allowNull: false, 
            defaultValue: 'Inactive' // Default status
        },
        updated: { type: DataTypes.DATE }, // Last updated timestamp
        isOnline: { type: DataTypes.BOOLEAN, defaultValue: false }, // Online status flag
        lastActive: { type: DataTypes.DATE }, // Last active timestamp
        isVerified: {
            type: DataTypes.VIRTUAL, // Virtual field (not stored in DB)
            get() { 
                // Returns true if either verified or passwordReset exists
                return !!(this.verified || this.passwordReset); 
            }
        }
    };

    // Model options configuration
    const options = {
        // Disable automatic createdAt and updatedAt fields
        timestamps: false,
        // Default scope applied to all queries
        defaultScope: {
            // Exclude passwordHash by default for security
            attributes: { exclude: ['passwordHash'] }
        },
        // Additional scope that includes passwordHash
        scopes: {
            withHash: { attributes: {} } // No attributes excluded
        }
    };

    // Create and return the Account model
    return sequelize.define('account', attributes, options);
}