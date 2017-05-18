#!/bin/bash

yum -y install python-setuptools epel-release
yum -y install ansible python-pip
pip install boto boto3
mkdir -p ~/.aws
touch ~/.aws/credentials
cp aws_credentials_template ~/.aws/credentials
export PYTHON_BIN=/usr/bin/python
