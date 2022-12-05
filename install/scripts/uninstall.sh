#!/bin/bash

installdir=/opt/dcnetio
if [ $(id -u) -ne 0 ]; then
    echo "Please run with sudo!"
    exit 1
fi
if [  -d $installdir ]; then
    echo "Uninstalling dc..."
    echo "Stopping dc..."
    $installdir/bin/dc stop all
    echo "Removing dc..."
    #remove  container name with dcnode
    docker ps -a | grep dcnode | awk '{print $1}' | xargs docker rm -f
    #remove  container name with dcupdate
    docker ps -a | grep dcupdate | awk '{print $1}' | xargs docker rm -f
    #remove  container name with dcchain
    docker ps -a | grep dcchain | awk '{print $1}' | xargs docker rm -f
    #remove  container name with dcpccs
    docker ps -a | grep dcpccs | awk '{print $1}' | xargs docker rm -f
    #remove  image tag with ghcr.io/dcnetio/dcnode
    docker images | grep dcnetio/dcnode | awk '{print $3}' | xargs docker rmi -f
    #remove  image tag with ghcr.io/dcnetio/dcupdate
    docker images | grep dcnetio/dcupdate | awk '{print $3}' | xargs docker rmi -f
    #remove  image tag with ghcr.io/dcnetio/dcchain
    docker images | grep dcnetio/dcchain | awk '{print $3}' | xargs docker rmi -f
    #remove  image tag with ghcr.io/dcnetio/pccs
    docker images | grep dcnetio/pccs | awk '{print $3}' | xargs docker rmi -f
    rm -rf $installdir
    rm -rf /usr/bin/dc
    rm -rf /etc/bash_completion.d/dc
    echo "Uninstalling dc done."
 else
    echo "dc is not installed!"
fi

