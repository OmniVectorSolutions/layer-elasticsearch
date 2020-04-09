#!/bin/bash

set -e

cert_password=$1

export ES_PATH_CONF=/etc/elasticsearch

echo $1 | /usr/share/elasticsearch/bin/elasticsearch-keystore add --stdin xpack.security.transport.ssl.truststore.secure_password
echo $1 | /usr/share/elasticsearch/bin/elasticsearch-keystore add --stdin xpack.security.transport.ssl.keystore.secure_password
