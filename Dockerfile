# Simple Dockerfile for the Cloudflare Tester Demo app
FROM node:20-alpine

# Create app directory
WORKDIR /usr/src/app

# Install dependencies (only package*.json first for better caching)
COPY package*.json ./
RUN npm install --only=production

# Copy app source
COPY . .

# Expose the default port
EXPOSE 3000

# Run the app
CMD ["node", "server.js"]

