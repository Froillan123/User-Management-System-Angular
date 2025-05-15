# 🚀 User Management System

<div align="center">

![User Management System](frontend/src/assets/images/favico.png)

A full-stack application for managing user accounts with advanced features and security.

[![Angular](https://img.shields.io/badge/Angular-DD0031?style=for-the-badge&logo=angular&logoColor=white)](https://angular.io/)
[![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Docker-2CA5E0?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)

</div>

## 📋 Table of Contents
- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Configuration](#-configuration)
- [API Documentation](#-api-documentation)
- [Deployment](#-deployment)
- [Contributing](#-contributing)
- [Developer](#-developer)

## ✨ Features

### 🔐 Authentication & Authorization
- User Registration with Email Verification
- JWT Authentication with Refresh Tokens
- Role-Based Access Control (Admin/User)
- Password Reset via Email
- Account Status Management (Active/Inactive)

### 📱 User Interface
- Modern and Responsive Design
- User-friendly Dashboard
- Account Management Interface
- Profile Settings
- Admin Control Panel

### 🛡️ Security
- Password Encryption
- Token-based Authentication
- Secure Email Verification
- Session Management
- Input Validation

## 🛠️ Tech Stack

### Frontend
- **Framework**: Angular 17
- **UI Library**: Bootstrap 5
- **Icons**: Font Awesome 6
- **HTTP Client**: Angular HttpClient
- **Forms**: Reactive Forms
- **Routing**: Angular Router

### Backend
- **Runtime**: Node.js
- **Framework**: Express.js
- **Database**: PostgreSQL
- **ORM**: Sequelize
- **Authentication**: JWT
- **Email**: Nodemailer
- **Validation**: Joi
- **Documentation**: Swagger UI

## 🚀 Getting Started

### Prerequisites
- Node.js (v18 or higher)
- PostgreSQL
- npm or yarn
- Angular CLI

### Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/Froillan123/User-Management-System-Angular.git
   cd User-Management-System-Angular
   ```

2. **Backend Setup**
   ```bash
   cd backend
   npm install
   ```

   Create `config.json`:
   ```json
   {
     "database": {
       "url": "postgresql://postgres:your_password@your_host:5432/your_database"
     },
     "secret": "your_jwt_secret",
     "emailFrom": "your_email@gmail.com",
     "smtpOptions": {
       "host": "smtp.gmail.com", 
       "port": 465,
       "secure": true,
       "auth": {
         "user": "your_email@gmail.com",
         "pass": "your_app_password in gmail"
       }
     }
   }
   ```

3. **Frontend Setup**
   ```bash
   cd frontend
   npm install
   ```

## ⚙️ Configuration

### Environment Setup
1. Copy the example environment file:
   ```bash
   cp backend/.env.example backend/.env
   ```


### Email Configuration
1. Go to your Google Account settings
2. Enable 2-Step Verification
3. Generate an App Password:
   - Go to Security → App Passwords
   - Select 'Mail' and your device
   - Copy the generated password
4. Update the `SMTP_PASS` in your `.env` file with the generated password

### Database Configuration
1. Create a PostgreSQL database
2. Get your database connection URL


### Security Notes
- Keep your JWT secret key secure and unique
- Regularly rotate your email app password
- Use strong database passwords

## 📚 API Documentation

API documentation is available at `/api-docs` when the backend server is running. Key endpoints:

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /accounts/register | Register new user |
| POST | /accounts/authenticate | Login |
| POST | /accounts/verify-email | Verify email |
| POST | /accounts/forgot-password | Request password reset |
| GET | /accounts | Get all accounts (Admin) |
| PUT | /accounts/:id | Update account |

## 🌐 Deployment

### Backend Deployment (Render)
1. Create a new Web Service
2. Connect your repository
3. Configure:
   - Build Command: `cd backend && npm install`
   - Start Command: `cd backend && npm start`
   - Add environment variables

### Docker Deployment
```bash
# Build image
docker build -t user-management-backend ./backend

# Run container
docker run -p 4000:4000 user-management-backend
```

## 🤝 Contributing
1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 👨‍💻 Developer

<div align="center">
 <img src="https://avatars.githubusercontent.com/u/Froillan123" width="100" style="border-radius: 50%"/>

  
  **Edem Froillan Kim B.**
  
  Full Stack Developer • Class of 2025
  
  [![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Froillan123)
  [![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/yourusername)
</div>

---

<div align="center">
  Made with ❤️ by Edem Froillan Kim B.
</div>