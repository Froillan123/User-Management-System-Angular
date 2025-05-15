const { DataTypes } = require('sequelize');
// Lopez Employee CRUD - Defines the Employee model for database operations
module.exports = model;

function model(sequelize) {
    const attributes = {
        employeeId: { type: DataTypes.STRING, allowNull: false },         // Lopez: Unique employee identifier
        firstName: { type: DataTypes.STRING, allowNull: false },         // Lopez: Employee's first name (required)
        lastName: { type: DataTypes.STRING, allowNull: false },          // Lopez: Employee's last name (required)
        email: { type: DataTypes.STRING, allowNull: false },             // Lopez: Contact email (required)
        departmentId: { type: DataTypes.INTEGER, allowNull: false },     // Lopez: Department reference ID
        accountId: { type: DataTypes.INTEGER, allowNull: true },         // Lopez: Optional linked account ID
        position: { type: DataTypes.STRING },                            // Lopez: Job title/position
        hireDate: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },  // Lopez: Employment start date
        phone: { type: DataTypes.STRING },                              // Lopez: Contact number
        status: { type: DataTypes.ENUM('Active', 'Inactive'), allowNull: false, defaultValue: 'Active' },  // Lopez: Employment status
        created: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },   // Lopez: Record creation timestamp
        updated: { type: DataTypes.DATE }                                // Lopez: Last update timestamp
    };

    const options = {
        timestamps: false,  // Lopez: Disables automatic timestamp fields
        hooks: {
            beforeUpdate: async (employee) => {  // Lopez: Auto-updates 'updated' field before saving changes
                employee.updated = new Date();
            }
        }
    };

    // Lopez: Creates and returns the Employee model definition
    return sequelize.define('employee', attributes, options);
}