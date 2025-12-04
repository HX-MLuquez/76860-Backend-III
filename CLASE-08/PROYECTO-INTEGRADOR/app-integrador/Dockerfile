FROM node:20.11.0
WORKDIR /app
COPY package*.json ./
COPY nest-cli.json ./
COPY tsconfig*.json ./
COPY tsconfig.build.json ./
RUN npm install
COPY ./src ./src
COPY ./test ./test
EXPOSE 8080
CMD ["npm", "start"]
