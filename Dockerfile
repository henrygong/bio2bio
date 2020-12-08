FROM ubuntu:20.04

MAINTAINER Henry <hzgong@ucsc.edu>

ENV TZ=America/Los_Angeles
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN apt-get update && apt-get install -y zsh wget less vim python3-igraph libcairo2-dev python3-pip && pip3 install argparse ipfshttpclient web3 hexbytes cryptography pandas flask flask_wtf wtforms rusty-rlp cairocffi
RUN sed -i 's/0\.7\.0/0\.7\.1/g' /usr/local/lib/python3.8/dist-packages/ipfshttpclient/client/__init__.py

COPY . /app

WORKDIR /app/postToEth-master/scripts
ENTRYPOINT ["zsh"]
#CMD ["app/app.py"]
