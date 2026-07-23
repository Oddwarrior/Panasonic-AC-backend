FROM node:20-alpine

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
COPY package*.json ./

RUN npm ci --only=production

# Bundle app source
COPY . .

# Expose the port the app runs on (assumed 5005 based on .env.example)
EXPOSE 5005

# Start the application
CMD [ "npm", "start" ]

