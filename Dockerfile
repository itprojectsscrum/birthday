# syntax=docker/dockerfile:1

FROM node:16
WORKDIR /app
COPY ./package*.json ./
RUN yarn install --production
COPY . .
RUN yarn run build