# User Management System (Node.js + PostgreSQL + Sequelize)

A full-stack backend system for managing user accounts, including registration, email verification, login/logout, password reset, and role-based access control.

---

## 🚀 Features

- ✅ User Registration with Email Verification
- 🔐 Login with JWT & Refresh Token support
- 🔁 Secure Token Rotation and Revocation
- 🛡️ Role-Based Authorization (Admin/User)
- 📩 Password Reset via Email
- 📄 API Documentation via Swagger UI
- 🔍 Input Validation with Joi
- 📦 Sequelize ORM for PostgreSQL

---

## 🛠️ Tech Stack

- **Node.js** + **Express**
- **PostgreSQL** + **Sequelize**
- **JWT** + **bcryptjs**
- **Nodemailer** (Ethereal email)
- **Swagger UI** for API documentation
- **Thunder Client / Postman** for testing

---

## 📁 Project Structure


---

## locate the backend folder
```bash
cd backend
```

## ⚙️ Setup Instructions

### 1. 📦 Install dependencies

```bash
# Install base dependencies
npm install

# Install Express and middleware
npm install express dotenv body-parser cookie-parser cors rootpath

# Install Sequelize and PostgreSQL
npm install sequelize
npm install pg pg-hstore

# Install authentication and security
npm install bcryptjs jsonwebtoken express-jwt joi

# Install email and documentation
npm install nodemailer swagger-ui-express yamljs

# Install development dependencies
npm install --save-dev nodemon
```

### 2. 🐳 Docker Setup (Optional)

If you're using Docker, the Dockerfile is already configured with PostgreSQL dependencies. Build and run with:

```bash
# Build the Docker image
docker build -t groupk-backend .

# Run the container
docker run -p 4000:4000 groupk-backend
```

▶️ Run the app
```bash
npm run dev
Visit: http://localhost:4000
```

🔑 API Endpoints
Method | Endpoint | Description
POST | /accounts/register | Register new user
POST | /accounts/authenticate | Login
POST | /accounts/refresh-token | Refresh JWT
POST | /accounts/revoke-token | Revoke a refresh token
POST | /accounts/verify-email | Verify email with token
POST | /accounts/forgot-password | Request password reset
POST | /accounts/reset-password | Reset password via token
GET | /accounts/ | Admin: View all accounts
GET | /accounts/:id | View account by ID

📚 API Documentation
Visit: http://localhost:4000/api-docs/#/

🧪 Test User Registration
Example JSON body:
{
  "title": "Mr",
  "firstName": "John",
  "lastName": "Doe",
  "email": "john.doe@email.com",
  "password": "Test1234",
  "confirmPassword": "Test1234",
  "acceptTerms": true
}

📩 Email 
Use Real Email for Registering an Account. See the token on spam for the link of the token

👨‍💻 Made by
Edem Froillan Kim B. 2025 🚀
