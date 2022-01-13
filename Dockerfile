
FROM ubuntu:latest

RUN mkdir /px &&\
 mkdir /px/config

COPY ./.output/linux-amd64-client /px/linux-amd64-client

CMD exec /px/linux-amd64-client
