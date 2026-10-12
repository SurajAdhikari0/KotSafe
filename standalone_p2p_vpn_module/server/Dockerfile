FROM node:24-alpine
WORKDIR /srv/p2p
COPY package.json ./
COPY server ./server
RUN addgroup -S p2p && adduser -S p2p -G p2p
USER p2p
EXPOSE 9443
CMD ["node", "server/start.js"]
