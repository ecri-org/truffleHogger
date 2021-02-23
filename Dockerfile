FROM docker.io/python:3-alpine

ARG RELEASE=3.0.0
ARG WHEEL_FILE=truffleHogger-${RELEASE}-py2.py3-none-any.whl
ARG DEST_FILE=/tmp/$WHEEL_FILE

COPY ./dist/$WHEEL_FILE $DEST_FILE

RUN adduser -S truffleHogger

RUN apk add --no-cache git && \
    pip install $DEST_FILE && \
    rm -Rf $DEST_FILE

USER truffleHogger
WORKDIR /proj
ENTRYPOINT [ "trufflehogger" ]
CMD [ "-h" ]
