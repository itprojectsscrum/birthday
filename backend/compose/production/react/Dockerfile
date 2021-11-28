FROM node:16 as build
WORKDIR /app
COPY ./package*.json ./
RUN npm install --production
COPY . .
ARG REACT_APP_NAME1
ENV REACT_APP_NAME1=$REACT_APP_NAME1

RUN npm run build

FROM nginx
COPY --from=build /app/build /usr/share/nginx/html
CMD ["nginx", "-g", "daemon off;"]
