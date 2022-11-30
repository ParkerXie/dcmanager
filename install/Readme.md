# DC

Official dc node service for running dc protocol.

## Preparation work

- Hardware requirements:

  CPU must contain **SGX module**, and make sure the SGX function is turned on in the bios, please click [this page](https://github.com/dcnetio/dcmanager/wiki/Check-TEE-supportive) to check if your machine supports SGX

- Operating system requirements:

  Ubuntu 20.04
  
- Other configurations

  - **Secure Boot** in BIOS needs to be turned off

## Install dependencies

### Install node service

```shell
sudo ./install.sh # Use 'sudo ./install.sh --registry cn' to accelerate installation in some areas
```

### Run service

- Please make sure the following ports are not occupied before starting：
  - 30334 9933 9944 (for dcchain)
  - 4006 6667 (for dcnode)
  - 6666 (for dcupdate)

```shell
sudo dc help
sudo dc start {}
sudo dc status
```

### Stop service

```shell
sudo crust stop
```

## License

[MIT](LICENSE)
