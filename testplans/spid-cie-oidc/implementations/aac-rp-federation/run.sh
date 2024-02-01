#!/bin/bash

cd $(dirname "$0") # Go to directory containing script

cd spid-cie-oidc-django

xhost +local:
sudo docker compose up
wait
xhost -local:
