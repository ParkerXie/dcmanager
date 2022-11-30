#!/bin/bash
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color


##必要软件安装
function install_base_depenencies(){
    ## 1. set to update /etc/apt/sources.list
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  1.0   set to update /etc/apt/sources.list' ${NC}

    # 1.1 backup sources.list
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  1.1   backup /etc/apt/sources.list' ${NC}
    sudo mv /etc/apt/sources.list /etc/apt/sources.list.old.$(date '+%Y%m%d%H%M%S')

    # 1.2 create new sources.list , with 777 privileges
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  1.2   create new sources.list , with 777 privileges' ${NC}
    sudo touch /etc/apt/sources.list
    sudo chmod 777 /etc/apt/sources.list

    # 1.3 set the aliyun sources 
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  1.3   set the  sources  for registry' ${NC}
    if [ $1 = "cn" ]; then
        echo "deb http://mirrors.aliyun.com/ubuntu/ bionic main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb http://mirrors.aliyun.com/ubuntu/ bionic-security main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb http://mirrors.aliyun.com/ubuntu/ bionic-updates main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb http://mirrors.aliyun.com/ubuntu/ bionic-proposed main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb http://mirrors.aliyun.com/ubuntu/ bionic-backports main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb-src http://mirrors.aliyun.com/ubuntu/ bionic main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb-src http://mirrors.aliyun.com/ubuntu/ bionic-security main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb-src http://mirrors.aliyun.com/ubuntu/ bionic-updates main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb-src http://mirrors.aliyun.com/ubuntu/ bionic-proposed main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb-src http://mirrors.aliyun.com/ubuntu/ bionic-backports main restricted universe multiverse" >> /etc/apt/sources.list
    else
        echo "deb http://archive.ubuntu.com/ubuntu/ bionic main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb http://archive.ubuntu.com/ubuntu/ bionic-security main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb http://archive.ubuntu.com/ubuntu/ bionic-updates main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb http://archive.ubuntu.com/ubuntu/ bionic-proposed main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb http://archive.ubuntu.com/ubuntu/ bionic-backports main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb-src http://archive.ubuntu.com/ubuntu/ bionic main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb-src http://archive.ubuntu.com/ubuntu/ bionic-security main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb-src http://archive.ubuntu.com/ubuntu/ bionic-updates main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb-src http://archive.ubuntu.com/ubuntu/ bionic-proposed main restricted universe multiverse" >> /etc/apt/sources.list
        echo "deb-src http://archive.ubuntu.com/ubuntu/ bionic-backports main restricted universe multiverse" >> /etc/apt/sources.list
    fi
    ## 1.4 update apt-get
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  1.4.   sudo apt-get update' ${NC}
    sudo apt-get update || 
    if [ $? -ne 0 ]; then
        echo -e ${RED} "1.4.   sudo apt-get update failed" ${NC} ${NC} && exit 
    fi
    ## 1.5 upgrade apt-get
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  1.5.   sudo apt-get upgrade' ${NC}
    sudo apt-get upgrade -y 
    if [ $? -ne 0 ]; then
        echo -e ${RED} "1.5.   sudo apt-get upgrade failed" ${NC} ${NC} && exit 
    fi

    ## 1.6 install build-essential 
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  1.6.   sudo apt install build-essential' ${NC}
    sudo apt-get -y install  build-essential 
    if [ $? -ne 0 ]; then
        echo -e ${RED} "1.6.   sudo apt install build-essential failed" ${NC} ${NC} && exit 
    fi

    ## 1.7 install libssl-dev 
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  1.7.   sudo apt install  libssl-dev' ${NC}
    sudo apt-get -y install   libssl-dev  
    if [ $? -ne 0 ]; then
        echo -e ${RED} "1.7.   sudo apt install  libssl-dev failed" ${NC} ${NC} && exit 
    fi

    ## 1.8 install dkms
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  1.8.   sudo apt install  dkms' ${NC}
    sudo apt-get  -y install dkms 
    if [ $? -ne 0 ]; then
        echo -e ${RED} "1.8.   sudo apt install  dkms failed" ${NC} ${NC} && exit 
    fi

    ## 1.9 install git 
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  1.9.   sudo apt-get  install  git' ${NC}
    sudo apt-get -y install  git 

}

 ## 2.0 sgx驱动安装
function install_sgx_env(){
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  2.0   download and  install sgx_linux_x64_driver_1.41.bin' ${NC}
    if [ ! -x /opt/intel/sgxdriver ]; then
        FILE=sgx_linux_x64_driver_1.41.bin
        if [[ ! -f "$FILE" ]]; then
            wget https://download.01.org/intel-sgx/sgx-dcap/1.12/linux/distro/ubuntu20.04-server/sgx_linux_x64_driver_1.41.bin
        fi
        result=$(echo '381c32da43ad500bac104601341c8f53f63e4e6f507259b463fa920b3e67bc4f sgx_linux_x64_driver_1.41.bin' | sha256sum -c | grep 'OK')
        if [[ $result = "" ]]; then 
        echo -e ${RED} "2.0. sgx_linux_x64_driver_1.41.bin checksum failed" ${NC} && exit  ${NC}
        exit 
        fi
        chmod +x sgx_linux_x64_driver_1.41.bin
        sudo ./sgx_linux_x64_driver_1.41.bin
        if [ $? -ne 0 ]; then
            echo -e ${RED} "2.0  install sgx_linux_x64_driver_1.41.bin failed" ${NC} ${NC} && exit 
        fi
    else
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  2.0  ******* sgx_driver aleady installed ********' ${NC}
    fi

    ## 2.1 queto provider安装
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  2.1   apt-key add intel-sgx-deb.key' ${NC}
    FILE=intel-sgx-deb.key
    if [[ ! -f "$FILE" ]]; then
        wget  https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
    fi
    result=$(echo '809cb39c4089843f923143834550b185f2e6aa91373a05c8ec44026532dab37c intel-sgx-deb.key' | sha256sum -c | grep 'OK')
    if [[ $result = "" ]]; then 
    echo -e ${RED} "2.1. intel-sgx-deb.key checksum failed" ${NC} && exit  ${NC}
    fi
    sudo apt-key add intel-sgx-deb.key
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
    sudo apt-get update -y 
    if [ $? -ne 0 ]; then
        echo -e ${RED} "apt-get update failed" ${NC} ${NC} && exit 
    fi
    ## 2.2 libsgx-dcap-default-qpl 安装
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  2.2   download and  install libsgx-dcap-default-qpl' ${NC}
    sudo apt-get install libsgx-dcap-default-qpl 
    if [ $? -ne 0 ]; then
        echo -e ${RED} "2.2   download and  install libsgx-dcap-default-qpl failed" ${NC} ${NC} && exit 
    fi
    FILE=/usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so
    if [[  -f "$FILE" ]]; then
        sudo rm -rf /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so
    fi
    sudo ln -s /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1 /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so
    if [ $? -ne 0 ]; then
        echo -e ${RED} "2.2 create soft link for /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so  failed: $? " ${NC} ${NC} && exit 
        exit
    fi

    ## 2.3 config /etc/sgx_default_qcnl.conf
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  2.3   config /etc/sgx_default_qcnl.conf' ${NC}
    sudo sed -i 's/.*use_secure_cert":.*/  "use_secure_cert": false,/' /etc/sgx_default_qcnl.conf
    sudo sed -i 's/\/\/"pccs_api_version": "3.1",/  "pccs_api_version": "3.1",/' /etc/sgx_default_qcnl.conf

    ## 2.4 libsgx-dcap-default-qpl 安装
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  2.4   download and  install libsgx-enclave-common' ${NC}
    sudo apt-get -y install  --no-install-recommends libsgx-enclave-common 
    if [ $? -ne 0 ]; then
        echo -e ${RED} "2.4   download and  install libsgx-enclave-common failed" ${NC} ${NC} && exit 
    fi
    ## 2.5 libsgx-dcap-default-qpl 安装
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  2.5   download and  install libsgx-quote-ex' ${NC}
    sudo apt-get -y install libsgx-quote-ex 
    if [ $? -ne 0 ]; then
        echo -e ${RED} "2.5   download and  install libsgx-quote-ex failed" ${NC} ${NC} && exit 
    fi
    ## 2.6 检查sgx相关驱动与软件是否安装成功
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  2.6   check if sgx env init success' ${NC}
    /sbin/modprobe intel_sgx
    if [ $? -ne 0 ]; then
        echo -e ${RED} "2.6   modprobe intel_sgx failed" ${NC} ${NC} && exit 
    fi
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  2.6   sgx env init success' ${NC}
}

## 3.0 docker 安装
function install_docker(){
    #remove  docker installed by snap, if any.Because snap docker will cause file not exist error when run docker on bind mount
    sudo snap remove docker
    #docker_installation
    if [ ! -x /var/lib/docker ]; then
        echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  3.0   INSTALLING docker' ${NC}
        echo
        echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  3.1   install docker dependencies' ${NC}
                sudo apt-get install apt-transport-https ca-certificates curl software-properties-common -y
        echo
        echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  3.2   add docker’s official GPG key' ${NC}
                curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
        echo
        echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  3.3   set up the stable repository' ${NC}
            sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"	
        echo
        echo
        echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  3.4   update the packages' ${NC}
            sudo apt-get update -y
        echo
        echo
        echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  3.5   checks install from the Docker repo instead of the default Ubuntu repo' ${NC}
            sudo apt-cache policy docker-ce 
        echo
        echo
        echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  3.6   installing dcoker through docker-ce' ${NC}
            sudo apt-get install docker-ce -y 
        echo
        echo
        echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  3.7   installing docker-compose' ${NC}
            sudo apt-get install docker-compose -y
        echo
        echo
        echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  3.8   adds your username to the docker group'  ${NC}
            sudo usermod -aG docker ${USER} 
        echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  3.9   docker successfully installed' ${NC}
        echo
        echo
    else
        #判断docker-compose是否已经存在，如果不存在则进行安装
        if ! [ -x "$(command -v docker-compose)" ]; then
            echo
            echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  3.4   update the packages' ${NC}
                sudo apt-get update -y
            echo
            echo
            echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  3.7   installing docker-compose' ${NC}
                sudo apt-get install docker-compose -y
            echo
            echo
        fi
        echo
        echo
                echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  3.9  DOCKER ALREADY INSTALLED'${NC}
        echo
        echo
    fi
    #Configure Docker to start on boot with systemd
    systemctl enable docker.service
    systemctl enable containerd.service
    #if docker is not running, start docker
    if ! systemctl is-active --quiet docker.service; then
        systemctl start docker.service
    fi
   #if containerd is not running, start containerd
    if ! systemctl is-active --quiet containerd.service; then
        systemctl start containerd.service
    fi
}


## 4.0 下载 docker 镜像
function install_docker_images(){
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  4.0   pull image from ghcr.io/dcnetio/pccs' ${NC}
    echo
    docker pull ghcr.io/dcnetio/pccs:latest
    if [ $? -ne 0 ]; then
        echo -e ${RED} "4.0   pull image from ghcr.io/dcnetio/pccs failed" ${NC} ${NC} && exit
    fi
    echo
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  4.1   pull image from ghcr.io/dcnetio/dcchain' ${NC}
    echo
    docker pull ghcr.io/dcnetio/dcchain:0.0.1
    if [ $? -ne 0 ]; then
        echo -e ${RED} "4.1   pull image from ghcr.io/dcnetio/dcchain failed" ${NC} ${NC} && exit 
    fi
    echo
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  4.2   pull image from ghcr.io/dcnetio/dcupdate' ${NC}
    echo
    docker pull ghcr.io/dcnetio/dcupgrade:latest
    if [ $? -ne 0 ]; then
        echo -e ${RED} "4.2   pull image from ghcr.io/dcnetio/dcupdate failed" ${NC} ${NC} && exit 
    fi
    echo
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  4.3   pull image from ghcr.io/dcnetio/dcnode' ${NC}
    echo
    docker pull ghcr.io/dcnetio/dcnode:0.0.1
    if [ $? -ne 0 ]; then
        echo -e ${RED} "4.3   pull image from ghcr.io/dcnetio/dcnode failed" ${NC} ${NC} && exit 
    fi
    echo

}


## 4.0-cn 从 ghcr.nju.edu.cn下载 docker 镜像 
function install_docker_images_cn(){
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  4.0   pull image from ghcr.nju.edu.cn/dcnetio/pccs' ${NC}
    echo
    docker pull ghcr.nju.edu.cn/dcnetio/pccs:latest
    if [ $? -ne 0 ]; then
        echo -e ${RED} "4.0   pull image from ghcr.nju.edu.cn/dcnetio/pccs failed" ${NC} ${NC} && exit 
    fi
    echo
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  4.1   pull image from ghcr.nju.edu.cn/dcnetio/dcchain' ${NC}
    echo
    docker pull ghcr.nju.edu.cn/dcnetio/dcchain:0.0.1
    if [ $? -ne 0 ]; then
        echo -e ${RED} "4.1   pull image from ghcr.nju.edu.cn/dcnetio/dcchain failed" ${NC} ${NC} && exit 
    fi
    echo
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  4.2   pull image from ghcr.nju.edu.cn/dcnetio/dcupdate' ${NC}
    echo
    docker pull ghcr.nju.edu.cn/dcnetio/dcupgrade:latest
    if [ $? -ne 0 ]; then
        echo -e ${RED} "4.2   pull image from ghcr.nju.edu.cn/dcnetio/dcupdate failed" ${NC} ${NC} && exit 
    fi
    echo
    echo -e ${GREEN} $(date '+%Y-%m-%d %H:%M:%S') '>>  4.3   pull image from ghcr.nju.edu.cn/dcnetio/dcnode' ${NC}
    echo
    docker pull ghcr.nju.edu.cn/dcnetio/dcnode:0.0.1
    if [ $? -ne 0 ]; then
        echo -e ${RED} "4.3   pull image from ghcr.nju.edu.cn/dcnetio/dcnode failed" ${NC} ${NC} && exit 
    fi
    echo

}




