FROM mcr.microsoft.com/playwright:v1.57.0-noble

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

RUN npm run build

EXPOSE 3000

CMD ["node", "server.js"]
