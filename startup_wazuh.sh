#!/bin/bash
 
git clone https://github.com/wazuh/wazuh-docker.git -b v4.13.1
 
cd wazuh-docker/single-node
 
mkdir config/wazuh_indexer_ssl_certs
 
docker compose -f generate-indexer-certs.yml run --rm generator
 
chmod -R 755 ./config/wazuh_indexer_ssl_certs
 
docker compose up -d