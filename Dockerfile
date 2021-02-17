FROM docker.io/python:3-alpine

ARG DIST_FILE=dist/truffleHogger-3.0.0-py2.py3-none-any.whl
COPY $DIST_FILE /tmp/$DIST_FILE

RUN ls -la /tmp/

RUN adduser -S truffleHogger

RUN apk add --no-cache git && \
    pip install /tmp/$DIST_FILE && \
    rm -Rf /tmp/$DIST_FILE

USER truffleHogger
WORKDIR /proj
ENTRYPOINT [ "trufflehogger" ]
CMD [ "-h" ]
