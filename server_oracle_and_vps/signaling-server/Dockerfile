FROM node:20-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY index.js ./
EXPOSE 8081
USER node
CMD ["node", "index.js"]
