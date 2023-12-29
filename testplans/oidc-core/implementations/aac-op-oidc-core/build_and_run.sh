#!/bin/bash

# local build AAC image ---
#git clone -b 4.x https://github.com/scc-digitalhub/AAC.git 
#cp edited_files/Dockerfile-aac ./AAC/
#cd AAC
#sudo docker build -t aac:latest --file Dockerfile-aac .
#cd ..
# local build AAC image ---

# uncomment for local build RP image ---
#cd relying-party-java
#sudo docker build -t rp-java:latest  .
#cd ..
# local build RP image ---

# local build i-mig-t --------
#cd ../../../../tools/i-mig-t
#rm mig-t-beta-jar-with-dependencies.jar
#sudo docker build -t i-mig-t .
#cd ../../testplans/spid-cie-oidc/implementations/aac-op-oidc-core/
# local build i-mig-t --------

xhost +local:
sudo docker compose up --remove-orphans
wait
xhost -local:
