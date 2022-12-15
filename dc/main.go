package main

import (
	"fmt"
	_ "net/http/pprof"
	"os"

	"github.com/dcnetio/dc/command"
	"github.com/dcnetio/dc/config"
	"github.com/dcnetio/dc/util"
	logging "github.com/ipfs/go-log/v2"
)

var log = logging.Logger("dcmanager")

// logpath := "./log"
const logpath = "/opt/dcnetio/log"

func main() {
	args := fmt.Sprintf("%v", os.Args)
	//trim square brackets
	args = args[1 : len(args)-1]
	// if don't run with root, exit
	if os.Geteuid() != 0 {
		fmt.Printf("Please run with root privilege.Usage: sudo %s \r\n", args)
		os.Exit(1)
	}
	util.SetupDefaultLoggingConfig(logpath)
	//判断配置文件是否存在
	_, err := os.Stat(config.Config_file_path)
	if err != nil {
		if os.IsNotExist(err) { //文件不存在，将默认配置更新到配置文件
			//创建目录
			if err = config.SaveConfig(config.RunningConfig); err != nil {
				return
			}
		} else {
			return
		}
	}
	//读取配置文件
	if config.RunningConfig, err = config.ReadConfig(); err != nil {
		log.Fatalf("read config file fail,err: %v", err)
		return
	}
	//判断chainNodeName是否为空,如果为空，生成一个随机的chainNodeName
	if config.RunningConfig.ChainNodeName == "" {
		config.RunningConfig.ChainNodeName = "dcnet_" + util.RandStringBytes(8)
		if err = config.SaveConfig(config.RunningConfig); err != nil {
			return
		}
	}
	//读取命令行参数，并解析响应
	if len(os.Args) == 1 { //显示帮助
		command.ShowHelp()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "start":
		command.StartCommandDeal()
	case "stop":
		command.StopCommandDeal()
	case "status":
		command.StatusCommandDeal()
	case "log":
		command.LogCommandDeal()
	case "upgrade":
		command.UpgradeCommandDeal()
	case "uniqueid":
		command.UniqueIdCommandDeal()
	case "peerinfo":
		command.PeerInfoCommandDeal()
	case "checksum":
		command.ChecksumCommandDeal()
	case "get":
		command.GetFileFromIpfsCommandDeal()
	case "rotate-keys":
		command.RotateKeyCommandDeal()
	default:
		command.ShowHelp()
	}
	os.Exit(1)
}
