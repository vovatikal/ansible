#!/bin/bash

yum -y install python-setuptools epel-release
yum -y install ansible python-pip
pip install boto boto3
mkdir -p ~/.aws
touch ~/.aws/credentials
cp aws_credentials_template ~/.aws/credentials
yum -y remove ansible

# Run manually:

# export PYTHON_BIN=/usr/bin/python
# source /opt/hacking/env-setup
# export PATH=$PATH=/opt/ansible/bin
