FROM node:20-alpine

WORKDIR /app

# Install dependencies first (better caching)
COPY package*.json ./
RUN npm install --production

# Copy app source
COPY . .

# Expose web port
EXPOSE 3000

# Environment defaults (can be overridden)
ENV NODE_ENV=production

CMD ["node", "src/app.js"]

