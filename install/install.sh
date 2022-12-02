#!/bin/bash

localbasedir=$(cd `dirname $0`;pwd)
localscriptdir=$localbasedir/scripts
localbindir=$localbasedir/bin
installdir=/opt/dcnetio
installbindir=$installdir/bin
installetcdir=$installdir/etc
datadir=$installdir/data
disksdir=$installdir/disks
source $localscriptdir/init.sh
region="en"


help()
{
cat << EOF
Usage:
    --registry {cn|en}       use registry to accelerate apt-get install  in some areas
EOF
exit 0
}

if [ $(id -u) -ne 0 ]; then
    echo -e ${RED} "Please run with sudo!" ${NC} && exit 
fi

while true ; do
    case "$1" in
        --registry)
            if [ x"$2" == x"" ] || [[ x"$2" != x"cn" && x"$2" != x"en" ]]; then
                help
            fi
            region=$2
            shift 2
            break ;;
        *)
            break;
            ;;
    esac
done



BEGINTIME=$(date "+%Y-%m-%d %H:%M:%S")
echo $BEGINTIME '>>  start dc  node install...'
USERNAME=$(getent passwd `who` | head -n 1 | cut -d : -f 1)
result=$(sudo cat /etc/sudoers |grep $USERNAME| grep 'ALL=(ALL:ALL)')
if [[ $result = "" ]]; then
    sudo chmod +w /etc/sudoers
    sudo echo $USERNAME "     ALL=(ALL:ALL) ALL" >> /etc/sudoers
    sudo chmod -w /etc/sudoers
fi
sudo cat  /etc/sudoers | grep $USERNAME
if [ ! -d $installdir ]; then
    sudo mkdir -p $installdir
fi
if [ ! -d $installbindir ]; then
    sudo mkdir -p $installbindir
fi
if [ ! -d $installetcdir ]; then
    sudo mkdir -p $installetcdir
fi
if [ ! -d $datadir ]; then
    sudo mkdir -p $datadir
fi
if [ ! -d $disksdir ]; then
    sudo mkdir -p $disksdir
fi
sudo cp -rf $localbindir/* $installbindir
sudo cp -rf $localbasedir/etc/* $installetcdir

sudo chmod +x $installbindir/*
sudo ln -s $installbindir/dc   /usr/bin/dc



install_base_depenencies $region
install_sgx_env
install_docker
if [ $region = "cn" ]; then
    install_docker_images_cn $installetcdir
else
    install_docker_images  $installetcdir
fi
install_sgx_env

ENDTIME=$(date "+%Y-%m-%d %H:%M:%S")
echo $ENDTIME '>>  end dc  node install...'
start_seconds=$(date --date="$BEGINTIME" +%s);
end_seconds=$(date --date="$ENDTIME" +%s);
echo "install time : "$((end_seconds-start_seconds))"s"

