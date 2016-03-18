FROM node
RUN mkdir /code
WORKDIR /code

COPY . /code

RUN npm install amqplib body-parser connect-mongo crypto express express-session jade oauth-percent-encode request --save

CMD node tweet-a-feeling.js
