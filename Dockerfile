FROM python:3-alpine
RUN apk add --no-cache git && pip install gitdb2==3.0.0 trufflehog
RUN adduser -S truffleHogger
USER truffleHogger
WORKDIR /proj
ENTRYPOINT [ "trufflehogger" ]
CMD [ "-h" ]
