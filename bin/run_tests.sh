#! /bin/bash

set -e

echo 'Building config...'
./bin/conf_gen.py

echo 'Running tests....'
coverage run -m pytest

echo 'Running report coverage....'
coverage report -m
