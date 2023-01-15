FROM node:alpine as build

WORKDIR /usr/src/app

COPY package.json package.json

RUN npm install
COPY . .
RUN npm run build

FROM nginx:1.23.1-alpine as run 

RUN rm -rf /usr/share/nginx/html
COPY --from=build /usr/src/app/dist/my-app /usr/share/nginx/html