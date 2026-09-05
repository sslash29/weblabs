FROM node:20-bullseye-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    file curl netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY . .
RUN mkdir -p uploads
EXPOSE 3000
CMD ["node", "server.js"]
