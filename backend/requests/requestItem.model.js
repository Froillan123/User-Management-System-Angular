const { DataTypes } = require('sequelize');

module.exports = model;

function model(sequelize) {
    const attributes = {
        requestId: { type: DataTypes.INTEGER, allowNull: false },
        name: { type: DataTypes.STRING, allowNull: false },
        quantity: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 1 },
        status: { 
            type: DataTypes.ENUM('Pending', 'Approved', 'Rejected'), 
            allowNull: false,
            defaultValue: 'Pending'
        }
    };

    const options = {
        timestamps: false
    };

    return sequelize.define('requestItem', attributes, options);
} 