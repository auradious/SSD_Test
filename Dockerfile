# Use official Node.js 22 Alpine base image
FROM node:22-alpine

# Create non-root user and group
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set working directory and change ownership to non-root user
WORKDIR /app
RUN chown appuser:appgroup /app

# Copy only dependency metadata first (for Docker layer caching)
COPY package*.json ./

# Install dependencies securely without running lifecycle scripts
RUN npm ci --ignore-scripts --no-audit --no-fund

# Copy the application code
COPY . .

# Ensure all files are owned by the app user
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose the port the app listens on
EXPOSE 3000

# Start the application
CMD ["node", "src/server.js"]
