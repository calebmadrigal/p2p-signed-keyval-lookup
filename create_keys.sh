#!/bin/bash

openssl req \
    -new \
    -newkey rsa:4096 \
    -days 365 \
    -nodes \
    -x509 \
    -subj "/C=US/ST=WI/L=Milwaukee/O=Northmars/CN=northmars.com" \
    -keyout server.key \
    -out server.crt
