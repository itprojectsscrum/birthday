FROM node:16

RUN mkdir -p /app && chown -R node:node /app

WORKDIR /app

COPY package*.json ./

USER node

RUN yarn install --production

COPY --chown=node:node . .

RUN yarn run build