# dcmanager
Official dc node service for running dc protocol.

## Preparation work
- Hardware requirements: 

  CPU must contain **SGX module**, and make sure the SGX function is turned on in the bios, please click [this page](https://github.com/dcnetio/dcmanager/wiki/Check-TEE-supportive) to check if your machine supports SGX

- Operating system requirements:

  Ubuntu 20.04
  
- Other configurations

  - **Secure Boot** in BIOS needs to be turned off

## Install dependencies

### Install dc service
```shell
sudo ./install.sh # Use 'sudo ./install.sh --registry cn' to accelerate installation in some areas
```

### Run service

- Please make sure the following ports are not occupied before starting：
  - 9933  9944 30333 9615 (for dcchain)
  - 6667 4006 (for dcnode)
  - 6666  (for dcupgrade)
  - 8081  (for PCCS)

```shell
sudo dc start  {node|chain|all} 
sudo dc status  {node|chain|all} 
```

### Stop service

```shell
sudo dc stop  {node|chain|all} 
```

## License

[MIT](LICENSE)
