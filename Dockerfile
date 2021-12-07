FROM node:16

RUN mkdir -p /app/node_modules && chown -R node:node /app

WORKDIR /app

COPY package*.json ./

USER node

RUN yarn install --production

COPY --chown=node:node . .

EXPOSE 8080

CMD [ "node", "app.js" ]