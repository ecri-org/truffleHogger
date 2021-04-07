FROM docker.io/python:3-alpine

ARG BUILD_VERSION="BAD-VERSION-SEE-PIPELINE"
ARG WHEEL_FILE=trufflehogger-${BUILD_VERSION}-py2.py3-none-any.whl
ARG DEST_FILE=/tmp/$WHEEL_FILE

COPY ./dist/$WHEEL_FILE $DEST_FILE

RUN adduser -S trufflehogger

RUN apk add --no-cache git && \
    pip install $DEST_FILE && \
    rm -Rf $DEST_FILE

USER trufflehogger
WORKDIR /proj
ENTRYPOINT [ "trufflehogger" ]
CMD [ "-h" ]
