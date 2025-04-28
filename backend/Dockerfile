# Use Node.js LTS version
FROM node:18-alpine

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
COPY package*.json ./

# Install all dependencies
RUN apk add --no-cache postgresql-client && \
    npm install && \
    npm install express dotenv body-parser cookie-parser cors rootpath && \
    npm install sequelize && \
    npm install pg pg-hstore && \
    npm install bcryptjs jsonwebtoken express-jwt joi && \
    npm install nodemailer swagger-ui-express yamljs && \
    npm install --save-dev nodemon && \
    npm install socket.io --save

# Copy the entire backend directory
COPY . .

# Expose the port the app runs on
EXPOSE 4000

# Command to run the application
CMD ["npm", "start"] 