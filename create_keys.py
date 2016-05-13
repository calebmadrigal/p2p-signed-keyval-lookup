#!/usr/bin/env python3

import subprocess

CREATE_KEYS_TEMPLATE = 'openssl req \
    -new \
    -newkey rsa:4096 \
    -days 365 \
    -nodes \
    -x509 \
    -subj "/C={}/ST={}/L={}/O={}/CN={}" \
    -keyout server.key \
    -out server.crt'


def create_keys(country='US', state='WI', city='Milwaukee', org='Northmars', website='northmars.com'):
    subprocess.check_call(CREATE_KEYS_TEMPLATE.format(country, state, city, org, website), shell=True)


if __name__ == '__main__':
    create_keys()

