package config

import (
	"io/ioutil"
	"log"
	"os"

	yaml "gopkg.in/yaml.v2"
)

//const Config_file_path = "./config/manage_config.yaml"

const Config_file_path = "/opt/dcnetio/etc/manage_config.yaml"
const Version = "0.0.1"
const CommitPubkeyHex = "0x3d14b9f8765c4c2e0a7b77805ebdad50ffbc74a7ee4aa606399693342a25483b" //技术委员会用于发布dcstorage升级版本的pubkey

var RunningConfig = &DcManageConfig{
	ChainNodeName:      "",
	ValidatorFlag:      false,
	ChainWsUrl:         "ws://127.0.0.1:9944",
	ChainRpcListenPort: 9933,
	PccsKey:            "", //intel pccs服务的订阅key
	ChainImage:         "ghcr.io/dcnetio/dcchain:latest",
	NodeImage:          "ghcr.io/dcnetio/dcstorage:latest",
	UpgradeImage:       "ghcr.io/dcnetio/dcupgrade:latest",
	PccsImage:          "ghcr.io/dcnetio/pccs:latest",
	Registry:           "ghcr.io/dcnetio",
}

type DcManageConfig struct {
	ChainNodeName      string `yaml:"chainNodeName"`
	ValidatorFlag      bool   `yaml:"validatorFlag"`
	ChainWsUrl         string `yaml:"chainWsUrl"`
	ChainRpcListenPort int    `yaml:"chainRpcListenPort"`
	PccsKey            string `yaml:"pccsKey"`
	ChainImage         string `yaml:"chainImage"`
	NodeImage          string `yaml:"nodeImage"`
	UpgradeImage       string `yaml:"upgradeImage"`
	PccsImage          string `yaml:"pccsImage"`
	Registry           string `yaml:"registry"`
}

func ReadConfig() (*DcManageConfig, error) {
	yamlFile, err := ioutil.ReadFile(Config_file_path)
	if err != nil {
		log.Fatalf("yamlFile.Get err #%v ", err)
		return nil, err
	}
	localconfig := &DcManageConfig{}
	err = yaml.Unmarshal(yamlFile, localconfig)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
		return nil, err
	}

	return localconfig, nil
}

func SaveConfig(config *DcManageConfig) (err error) {
	fileBytes, err := yaml.Marshal(config)
	if err != nil {
		log.Fatalf("Marshal: %v", err)
		return err
	}
	err = ioutil.WriteFile(Config_file_path, fileBytes, os.ModePerm)
	if err != nil {
		log.Fatalf("yamlFile.Save err #%v ", err)
		return err
	}

	return nil
}
