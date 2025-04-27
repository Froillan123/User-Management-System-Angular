# Use Node.js LTS version
FROM node:18-alpine

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
COPY package*.json ./

# Install dependencies including PostgreSQL client
RUN apk add --no-cache postgresql-client && \
    npm install && \
    npm install pg pg-hstore

# Copy config.json first to ensure it exists
COPY config.json ./

# Bundle app source
COPY . .

# Create .env file if it doesn't exist
RUN touch .env

# Expose the port the app runs on
EXPOSE 4000

# Command to run the application
CMD ["npm", "start"] 