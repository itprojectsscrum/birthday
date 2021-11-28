FROM node:16
WORKDIR /app
COPY ./package*.json ./
RUN npm install --production
COPY . .
ARG REACT_APP_NAME1
ENV REACT_APP_NAME1=$REACT_APP_NAME1

EXPOSE 3000

CMD ["npm", "start"]
