from python:3
MAINTAINER cb-developer-network@vmware.com

COPY . /app
WORKDIR /app

RUN pip install -r requirements.txt
RUN chmod +x bin/conf_gen.py
RUN chmod +x bin/run_tests.sh
