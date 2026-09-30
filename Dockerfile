FROM node:22-alpine
WORKDIR /app
COPY package.json server.js ./
COPY lib ./lib
COPY public ./public
USER node
ENV HOST=0.0.0.0 PORT=8080 HEADERSCAN_TRUST_PROXY=1
EXPOSE 8080
CMD ["node", "server.js"]
