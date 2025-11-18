#!/bin/bash

kind create cluster && make install && ./e2e/load-certs.sh 
kind load docker-image harbor.local/library/breakglass-2:v1 
kind load docker-image mailhog/mailhog:v1.0.1 
kind load docker-image quay.io/keycloak/keycloak:23.0.0 
kind load docker-image curlimages/curl:8.4.0
make deploy_dev
