FROM node:16 as build
WORKDIR /app
COPY ./package*.json ./
RUN npm install --production
COPY . .
ARG REACT_APP_NAME1
ENV REACT_APP_NAME1=$REACT_APP_NAME1
#COPY ./compose/production/react/start /start-react

FROM nginx
COPY --from=build /app/build /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
