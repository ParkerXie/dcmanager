package command

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bigkevmcd/go-configparser"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	"github.com/dcnetio/dc/blockchain"
	"github.com/dcnetio/dc/config"
	"github.com/dcnetio/dc/util"
	"github.com/dcnetio/gothreads-lib/core/thread"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	goversion "github.com/hashicorp/go-version"
	logging "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
)

const dcNodeListenPort = 6667
const dcUpgradeListenPort = 6666

const nodeContainerName = "dcnode"
const chainContainerName = "dcchain"
const upgradeContainerName = "dcupgrade"
const pccsContainerName = "dcpccs"
const nodeVolueName = "dcnode"
const chainVolueName = "dcchain"
const upgradeVolueName = "upgradeVolueName"
const pccsVolueName = "dcpccs"

var serviceConfigFileContent = `[Unit]
After=network.target

[Service]
ExecStart=/opt/dcnetion/bin/startup.sh

[Install]
WantedBy=default.target`

//servicename
const serviceConfigFile = "/etc/systemd/system/dc.service"

//const serviceConfigFile = "./test/dc.service"
const startupShell = "/opt/dcnetio/bin/startup.sh"
const dcBin = "/opt/dcnetio/bin"
const commitPubkeyHex = "0x3d14b9f8765c4c2e0a7b77805ebdad50ffbc74a7ee4aa606399693342a25483b" //技术委员会用于发布dcnode升级版本的pubkey

func ShowHelp() {
	fmt.Println("dcmanager version ", config.Version)
	fmt.Println("usage: dc command [options]")
	fmt.Println("command")
	fmt.Println("")
	fmt.Println(" start {node|chain|pccs|all}             start service with service_name")
	fmt.Println("                                         \"node\": start dcnode service")
	fmt.Println("                                         \"chain\": start dcchain service")
	fmt.Println("                                         \"pccs\": start local pccs service")
	fmt.Println("                                         \"all\": start dcnode and dcchain service")
	fmt.Println(" stop {node|chain|pccs|all}              stop service  with service_name")
	fmt.Println("                                         \"node\": stop dcnode service")
	fmt.Println("                                         \"chain\": stop dcchain service")
	fmt.Println("                                         \"pccs\": stop local pccs service")
	fmt.Println("                                         \"all\": stop dcnode and dcchain service")
	fmt.Println(" status {node|chain|all}                 check dc daemon status and  service status")
	fmt.Println("                                         \"node\": stop dcnode service")
	fmt.Println("                                         \"chain\": stop dcchain service")
	fmt.Println("                                         \"all\": stop dcnode and dcchain service")
	fmt.Println(" log  {node|chain|upgrade|pccs}          show running log with service_name")
	fmt.Println("                                         \"node\":  show dcnode container running log")
	fmt.Println("                                         \"chain\":  show dcchain container running log")
	fmt.Println("                                         \"upgrade\":  show dcupgrade container running log")
	fmt.Println("                                         \"pccs\":  show local pccs  running log")
	fmt.Println(" upgrade [options]                       upgrade dcnode to newest version that configed on blockchain")
	fmt.Println("                                         (options: \"daemon\"|\"cancel\"")
	fmt.Println("                                         \"daemon\": dcmanager will run in deamon mode,and auto updrage dcnode ")
	fmt.Println("                                         \"cancel\": cancel dcmanager deamon mode")
	fmt.Println("                                         when a new dcnode version configed on blockchain")
	fmt.Println(" uniqueid  {node|upgrade}                show soft version and sgx enclaveid ")
	fmt.Println(" checksum  filepath                      generate  sha256 checksum for file in the \"filepath\"")
	fmt.Println(" get cid [--name][--timeout][--secret]   get file from dc net with \"cid\" ")
	fmt.Println("                                         \"name\": file to save name")
	fmt.Println("                                         \"timeout\":  wait seconds for file to complete download")
	fmt.Println("                                         \"secret\":  file decode secret with base32 encoded")
	fmt.Println(" rotate-keys	                          upgrade dcnode to newest version that configed on blockchain")
}

var log = logging.Logger("dcmanager")

func StartCommandDeal() {
	if len(os.Args) < 3 {
		ShowHelp()
		return
	}
	switch os.Args[2] {
	case "node":
		err := startDcNode()
		if err == nil {
			showContainerLog(nodeContainerName)
		} else {
			log.Error(err)
		}

	case "chain":
		err := startDcChain()
		if err == nil {
			showContainerLog(chainContainerName)
		}
	case "pccs":
		err := runPccsInDocker()
		if err == nil {
			showContainerLog(pccsContainerName)
		}

	case "all":
		startDcChain()
		showLogsOnNewWindowForContainer(chainContainerName)
		err := startDcNode()
		if err == nil {
			showContainerLog(nodeContainerName)
		} else {
			log.Error(err)
		}

	default:
		ShowHelp()
	}

}

func StopCommandDeal() {
	if len(os.Args) < 2 {
		ShowHelp()
		return
	}
	switch os.Args[2] {
	case "node":
		stopDcnodeInDocker()
	case "chain":
		stopDcchainInDocker()
	case "pccs":
		stopPccsInDocker()
	case "all":
		stopDcnodeInDocker()
		stopDcchainInDocker()
		stopPccsInDocker()
	default:
		ShowHelp()
	}
}

//获取程序的运行状态
func StatusCommandDeal() {
	if len(os.Args) < 2 {
		ShowHelp()
		return
	}
	secondArgs := "all"
	if len(os.Args) > 2 {
		secondArgs = os.Args[2]
	}
	dcStatus, _ := checkDcDeamonStatusDc()
	fmt.Println("daemon status:", dcStatus)
	switch secondArgs {
	case "node":
		nodeStatus, _ := checkDcnodeStatus()
		fmt.Println("dcnode status:", nodeStatus)
	case "chain":
		chainStatus, _ := checkDcchainStatus()
		fmt.Println("dcchain status:", chainStatus)
	case "all":
		nodeStatus, _ := checkDcnodeStatus()
		fmt.Println("dcnode status:", nodeStatus)
		chainStatus, _ := checkDcchainStatus()
		fmt.Println("dcchain status:", chainStatus)
	default:
		ShowHelp()
	}
}

//打印具体程序的实时运行日志
func LogCommandDeal() { //
	if len(os.Args) < 3 {
		ShowHelp()
		return
	}
	switch os.Args[2] {
	case "node":
		showContainerLog(nodeContainerName)
	case "chain":
		showContainerLog(chainContainerName)
	case "upgrade":
		showContainerLog(upgradeContainerName)
	case "pccs":
		showContainerLog(pccsContainerName)
	default:
		ShowHelp()
	}
}

//升级指令处理
func UpgradeCommandDeal() {
	if len(os.Args) > 2 {
		if os.Args[2] == "daemon" { //进入守护程序模式，自动下载并更新dcnode,同时设置为开机重启
			daemonCommandDeal()
		} else if os.Args[2] == "cancel" { //停止守护程序模式
			cancelDaemonCommandDeal()
		} else {
			ShowHelp()
		}
	} else { //手动升级模式
		upgradeDeal()
	}
}

//获取指定enclave的enclaveid
func UniqueIdCommandDeal() {
	if len(os.Args) < 3 {
		ShowHelp()
		return
	}
	fmtStr := "dcupgrade version: %s,enclaveid: %s"
	localport := 0
	switch os.Args[2] {
	case "node":
		localport = dcNodeListenPort
		fmtStr = "dcnode version: %s,enclaveid: %s"
	case "upgrade":
		localport = dcUpgradeListenPort
		fmtStr = "dcupgrade version: %s,enclaveid: %s"
	default:
		ShowHelp()
		return
	}
	version, enclaveId, err := getVersionByHttpGet(localport)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dcnode enclaveid get fail,err: %v\r\n", err)
	}
	log.Infof(fmtStr, version, enclaveId)
}

//生成文件的hash校验码
func ChecksumCommandDeal() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: dc checksum <file>")
		os.Exit(1)
	}
	for _, filename := range os.Args[2:] {
		checksum, err := util.Sha256sum(filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "checksum: %v\r\n", err)
			continue
		}
		fmt.Printf("%s\t%s\n", checksum, filename)
	}
}

//从dc网络下载文件
func GetFileFromIpfsCommandDeal() {
	if len(os.Args) < 4 {
		ShowHelp()
		return
	}
	cid := os.Args[2]

	ipfsCmd := flag.NewFlagSet("ipfs", flag.ExitOnError)
	name := ipfsCmd.String("name", cid, "")
	timeout := ipfsCmd.Int("timeout", 600, "")
	secret := ipfsCmd.String("secret", "", "")
	if len(os.Args) > 3 {
		ipfsCmd.Parse(os.Args[3:])
	}
	tTimeout := time.Duration(*timeout) * time.Second
	//根据cid从区块链中查询出存在该文件的节点
	fileSize, addrInfos, err := blockchain.GetPeerAddrsForCid(cid)
	if err != nil || len(addrInfos) == 0 {
		log.Infof("can't find any peers store the file with cid: %s ", cid)
		return
	}
	tObj := &util.TransmitObj{
		TotalSize: uint64(fileSize),
	}
	util.DownloadFromIpfs(cid, *secret, *name, addrInfos, tTimeout, tObj)
}

type SessionKeyRes struct {
	Jsonrpc string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Result  string `json:"result"`
}

func RotateKeyCommandDeal() (sessionKey string, err error) {
	//check dcchain status
	status, err := checkDcchainStatus()
	if err != nil {
		return "", err
	}
	if !status {
		return "", errors.New("dcchain is not running")
	}
	//make http request to dcchain
	chainRpcUrl := fmt.Sprintf("http://127.0.0.1:%d", config.RunningConfig.ChainRpcListenPort)
	postData := `"id":1, "jsonrpc":"2.0", "method": "author_rotateKeys", "params":[]}`
	res, err := util.HttpPost(chainRpcUrl, []byte(postData))
	if err != nil {
		fmt.Fprintf(os.Stderr, "request author_rotateKeys fail,  err: %v\r\n", err)
		return
	}
	var sessionKeyRes SessionKeyRes
	err = json.Unmarshal(res, &sessionKeyRes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse res author_rotateKeys failed,  err: %v\r\n", err)
		return
	}
	sessionKey = sessionKeyRes.Result
	return
}

//获取dcnode的运行状态
func checkDcnodeStatus() (status bool, err error) {
	status = false
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return
	}
	defer cli.Close()
	//查看dcnode容器是否存在
	resp, err := cli.ContainerInspect(context.Background(), nodeContainerName)
	if err != nil {
		return
	} else if resp.State.Running {
		status = true
	}
	return
}

//获取dcchain的运行状态
func checkDcchainStatus() (status bool, err error) {
	status = false
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return
	}
	defer cli.Close()
	//查看dcchain容器是否存在
	resp, err := cli.ContainerInspect(context.Background(), chainContainerName)
	if err != nil {
		return
	} else if resp.State.Running {
		status = true
	}
	return
}

//获取dcmanager的运行状态
func checkDcDeamonStatusDc() (status bool, err error) {
	// Look for the dcmanager process.
	status = false
	//read content from .dcdaemon
	content, err := ioutil.ReadFile(".dcdaemon")
	if err != nil {
		return
	}
	//get pid from .dcdaemon
	pid, err := strconv.Atoi(string(content))
	if err != nil {
		log.Errorf("get pid from .dcdaemon file error:%v", err)
		return
	}
	//get current process id
	currentPid := os.Getpid()
	if pid == currentPid {
		status = true
	}
	return
}

//后台升级跟踪处理
func daemonCommandDeal() {
	_, err := os.Stat(".dcdaemon")
	if err != nil {
		if os.IsNotExist(err) {
			os.Create(".dcdaemon")
		} else {
			fmt.Fprintf(os.Stderr, "check dcmanager daemon status fail,err: %v\r\n", err)
			return
		}
	}
	//read content from .dcdaemon
	content, err := ioutil.ReadFile(".dcdaemon")
	if err != nil {
		fmt.Fprintf(os.Stderr, "read .dcdaemon file error:%v\r\n", err)
		return
	}
	//check if the content is empty
	if len(content) == 0 {
		//write the current pid to .dcdaemon
		err = ioutil.WriteFile(".dcdaemon", []byte(strconv.Itoa(os.Getpid())), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "write .dcdaemon file error:%v\r\n", err)
			return
		}
	} else {
		//check if the pid is running
		pid, err := strconv.Atoi(string(content))
		if err != nil {
			fmt.Fprintf(os.Stderr, "read .dcdaemon file error:%v\r\n", err)
			return
		}
		//check if the pid is running
		_, err = os.FindProcess(pid)
		if err == nil {
			fmt.Fprintf(os.Stderr, "dcmanager daemon already on running\r\n")
			return
		}
		//write the current pid to .dcdaemon
		err = ioutil.WriteFile(".dcdaemon", []byte(strconv.Itoa(os.Getpid())), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "write .dcdaemon file error:%v\r\n", err)
			return
		}
	}
	flag := configServiceStartup()
	if !flag {
		fmt.Fprintf(os.Stderr, "set auto upgrade service to run with startup fail\r\n")
		return
	}
	//start upgrade
	ticker := time.NewTicker(time.Hour)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	for {
		select {
		case <-ticker.C:
			upgradeDeal()
		case <-quit:
			os.Remove(".dcdaemon")
			os.Exit(1)
		}
	}
}

//退出守护程序模式
func cancelDaemonCommandDeal() {
	//remove startup service config
	flag := removeServiceStartup()
	if !flag {
		fmt.Fprintf(os.Stderr, "cancel auto upgrade service to run with startup fail\r\n")
	}
	_, err := os.Stat(".dcdaemon")
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "dcmanager daemon is not running\r\n")
			return
		} else {
			fmt.Fprintf(os.Stderr, "check dcmanager daemon status fail,err: %v\r\n", err)
			return
		}
	}
	//read content from .dcdaemon
	content, err := ioutil.ReadFile(".dcdaemon")
	if err != nil {
		fmt.Fprintf(os.Stderr, "read .dcdaemon file error:%v\r\n", err)
		return
	}
	//check if the content is empty
	if len(content) == 0 {
		fmt.Fprintf(os.Stderr, "dcmanager daemon is not running\r\n")
		return
	} else {
		//check if the pid is running
		pid, err := strconv.Atoi(string(content))
		if err != nil {
			fmt.Fprintf(os.Stderr, "read .dcdaemon file error:%v\r\n", err)
			return
		}
		//check if the pid is running
		process, err := os.FindProcess(pid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dcmanager daemon is not running\r\n")
			return
		}
		err = process.Kill()
		if err != nil {
			fmt.Fprintf(os.Stderr, "kill dcmanager daemon fail,err: %v\r\n", err)
			return
		}
		os.Remove(".dcdaemon")
	}
}

func startDcNode() (err error) {
	//判断pccs（docker）是否已经运行，没有运行，需要先运行
	err = runPccsInDocker()
	if err != nil {
		return
	}
	//判断dcnode是否已经运行，没有运行，需要先运行
	err = startDcnodeInDocker()
	return
}

func startDcChain() error {
	return startDcchainInDocker()
}

//start dcnode in docker
func startDcnodeInDocker() (err error) {
	ctx := context.Background()
	_, err = util.CreateVolume(ctx, nodeVolueName)
	if err != nil {
		return
	}
	logConfig := container.LogConfig{
		Type: "json-file",
		Config: map[string]string{
			"max-size": "100m",
			"max-file": "3",
		},
	}
	dataMount := mount.Mount{
		Type:   mount.TypeVolume,
		Source: nodeVolueName,
		Target: "/opt/dcnetio/data",
	}
	disksMount := mount.Mount{
		Type:        mount.TypeBind,
		Source:      "/opt/dcnetio/disks",
		Target:      "/opt/dcnetio/disks",
		Consistency: mount.ConsistencyDefault,
		BindOptions: &mount.BindOptions{
			Propagation: mount.PropagationShared,
		},
	}
	etcMount := mount.Mount{
		Type:   mount.TypeBind,
		Source: "/opt/dcnetio/etc/",
		Target: "/opt/dcnetio/etc/",
	}
	hostConfig := &container.HostConfig{
		RestartPolicy: container.RestartPolicy{
			Name: "always",
		},
		Mounts:      []mount.Mount{dataMount, disksMount, etcMount},
		NetworkMode: "host",
		Resources: container.Resources{
			Devices: []container.DeviceMapping{
				{
					PathOnHost:        "/dev/sgx/enclave",
					PathInContainer:   "/dev/sgx/enclave",
					CgroupPermissions: "rwm",
				},
				{
					PathOnHost:        "/dev/sgx/provision",
					PathInContainer:   "/dev/sgx/provision",
					CgroupPermissions: "rwm",
				},
			},
		},
		LogConfig: logConfig,
	}
	containerConfig := &container.Config{
		Image: config.RunningConfig.NodeImage,
	}
	//start container
	err = util.StartContainer(ctx, nodeContainerName, containerConfig, hostConfig)
	return
}

//start dcchain in docker
func startDcchainInDocker() (err error) {
	ctx := context.Background()
	_, err = util.CreateVolume(ctx, chainVolueName)
	if err != nil {
		return
	}
	logConfig := container.LogConfig{
		Type: "json-file",
		Config: map[string]string{
			"max-size": "100m",
			"max-file": "3",
		},
	}
	dataMount := mount.Mount{
		Type:   mount.TypeVolume,
		Source: chainVolueName,
		Target: "/opt/dcnetio/data",
	}
	hostConfig := &container.HostConfig{
		RestartPolicy: container.RestartPolicy{
			Name: "always",
		},
		Mounts:      []mount.Mount{dataMount},
		NetworkMode: "host",
		LogConfig:   logConfig,
	}
	var entrypoint []string
	entrypoint = append(entrypoint, "dcchain")
	entrypoint = append(entrypoint, "--chain=mainnet")
	entrypoint = append(entrypoint, "-d")
	entrypoint = append(entrypoint, "/opt/dcnetio/data")
	if config.RunningConfig.ValidatorFlag {
		entrypoint = append(entrypoint, "--validator")
	}
	entrypoint = append(entrypoint, "--name")
	entrypoint = append(entrypoint, config.RunningConfig.ChainNodeName)
	//判断

	containerConfig := &container.Config{
		Image:      config.RunningConfig.ChainImage,
		Entrypoint: entrypoint,
	}
	//start container
	err = util.StartContainer(ctx, chainContainerName, containerConfig, hostConfig)
	return

}

//start dcupgrade in docker
func startDcupgradeInDocker() (err error) {
	ctx := context.Background()
	dataMount := mount.Mount{
		Type:   mount.TypeVolume,
		Source: upgradeVolueName,
		Target: "/opt/dcnetio/data",
	}
	logConfig := container.LogConfig{
		Type: "json-file",
		Config: map[string]string{
			"max-size": "10m",
			"max-file": "3",
		},
	}
	hostConfig := &container.HostConfig{
		RestartPolicy: container.RestartPolicy{
			Name: "always",
		},
		Mounts:      []mount.Mount{dataMount},
		NetworkMode: "host",
		Resources: container.Resources{
			Devices: []container.DeviceMapping{
				{
					PathOnHost:        "/dev/sgx/enclave",
					PathInContainer:   "/dev/sgx/enclave",
					CgroupPermissions: "rwm",
				},
				{
					PathOnHost:        "/dev/sgx/provision",
					PathInContainer:   "/dev/sgx/provision",
					CgroupPermissions: "rwm",
				},
			},
		},
		LogConfig: logConfig,
	}
	containerConfig := &container.Config{
		Image: config.RunningConfig.UpgradeImage,
	}
	//start container
	util.StartContainer(ctx, upgradeContainerName, containerConfig, hostConfig)
	return
}

//stop dcnode in docker
func stopDcnodeInDocker() (err error) {
	ctx := context.Background()
	err = util.StopContainer(ctx, nodeContainerName)
	return
}

//stop dcchain in docker
func stopDcchainInDocker() {
	ctx := context.Background()
	util.StopContainer(ctx, chainContainerName)

}

//stop dcpccs in docker
func stopPccsInDocker() {
	ctx := context.Background()
	util.StopContainer(ctx, pccsContainerName)

}

//利用dcnode以及dcupdate程序提供本地随机数查询服务，获取它们对应的enclavid
func getVersionByHttpGet(localport int) (version string, enclaveId string, err error) {
	dcEnclaveIdUrl := fmt.Sprintf("http://127.0.0.1:%d/version", localport)
	respBody, err := util.HttpGet(dcEnclaveIdUrl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request teerandom fail,  err: %v\r\n", err)
		return
	}
	versionInfo := string(respBody)
	values := strings.Split(versionInfo, "@")
	if len(values) != 2 {
		fmt.Println("get invalid version info")
	} else {
		enclaveId = values[0]
		version = values[1]
	}
	return

}

//升级过程，等待dcupdate从dcnode获取节点密钥
func waitDcUpdateGetPeerSecret() (bool, error) {
	dcSecretFlagUrl := fmt.Sprintf("http://127.0.0.1:%d/secretflag", dcUpgradeListenPort)
	ticker := time.NewTicker(time.Second)
	count := 0
	for {
		<-ticker.C
		respBody, err := util.HttpGet(dcSecretFlagUrl)
		if err != nil {
			fmt.Fprintf(os.Stderr, "waitDcUpdateGetPeerSecret requset fail,  err: %v\r\n", err)
			return false, err
		}
		flag := string(respBody)
		if flag == "true" {
			return true, nil
		} else {
			count++
			if count > 60 {
				return false, fmt.Errorf("dcupdate get peer secret timeout")
			}
			continue
		}
	}

}

//升级过程，等待新版本dcnode从dcupdate取走密钥
func waitNewDcGetPeerSecret() (bool, error) {
	dcSecretFlagUrl := fmt.Sprintf("http://127.0.0.1:%d/upgradeflag", dcUpgradeListenPort)
	ticker := time.NewTicker(time.Second)
	count := 0
	for {
		<-ticker.C
		respBody, err := util.HttpGet(dcSecretFlagUrl)
		if err != nil {
			fmt.Fprintf(os.Stderr, "waitNewDcGetPeerSecret requset fail,  err: %v\r\n", err)
			return false, err
		}
		flag := string(respBody)
		if flag == "true" {
			return true, nil
		} else {
			count++
			if count > 600 { //等待10分钟
				return false, fmt.Errorf("new version dcnode get peer secret timeout")
			}
			continue
		}
	}

}

//dcnode 程序升级处理
func upgradeDeal() (err error) {
	//判断当前dcnode是否在运行，如果没有运行，则启动dcnode
	startDcNode()
	//获取当前运行的dcnode的version与enclaveid
	version, _, err := getVersionByHttpGet(dcNodeListenPort)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dcnode enclaveid get fail,err: %v\r\n", err)
		log.Errorf("dcnode enclaveid get fail,err: %v", err)
		return
	}
	//获取区块链上配置的最新的version与enclaveid
	programInfo, err := blockchain.GetConfigedDcNodeInfo()
	if err != nil {
		fmt.Fprintf(os.Stderr, "get dcnode version info from blockchain fail,err: %v\r\n", err)
		log.Errorf("get dcnode version info from blockchain fail,err: %v", err)
		return
	}
	//利用委员会gongyyòng的公钥对enclaveid进行验证
	//生成技术委员会的pubkey
	commitPubkeyHexBytes, err := codec.HexDecodeString(commitPubkeyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		return
	}
	cpubkey, err := crypto.UnmarshalEd25519PublicKey(commitPubkeyHexBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client request secret fail, err: %v\r\n", err)
		log.Errorf("client request secret fail, err: %v\n", err)
		return
	}
	commitPubkey := thread.NewLibp2pPubKey(cpubkey)
	//验证enclaveid的签名
	ok, err := commitPubkey.Verify([]byte(programInfo.EnclaveId), []byte(programInfo.IdSignature))
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify enclaveid signature for dcnode with last version  fail, err: %v\n", err)
		log.Errorf("verify enclaveid signature for dcnode with last version  fail, err: %v", err)
		return
	}
	if !ok {
		fmt.Fprintf(os.Stderr, "verify enclaveid signature for dcnode with last version  fail\n")
		log.Error("verify enclaveid signature for dcnode with last version  fail")
		return
	}
	//比较版本号新旧，确定是否需要升级
	localVersion, err := goversion.NewVersion(version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid local version format,err: %v\r\n", err)
		log.Errorf("invalid local version format,err: %v", err)
		return
	}
	configedVersion, err := goversion.NewVersion(programInfo.Version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid new version format,err: %v\r\n", err)
		log.Errorf("invalid new version format,err: %v", err)
		return
	}
	if !localVersion.LessThan(configedVersion) { //本地版本更新，不更新
		fmt.Fprintf(os.Stdout, "unneed upgrade ,dcnode localVersion: %s,   configedVersion: %s\r\n", localVersion, configedVersion)
		return
	}
	//拉取新版本的dcnode程序image
	err = pullDcNodeImage(programInfo.Url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pull new version dcnode image fail, err: %v\r\n", err)
		log.Errorf("pull new version dcnode image fail, err: %v", err)
		return
	}
	//运行升级辅助程序
	err = startDcupgradeInDocker()
	if err != nil {
		return
	}
	//等待dcupdate成功获取节点密钥
	_, err = waitDcUpdateGetPeerSecret()
	if err != nil {
		fmt.Fprintf(os.Stderr, "update fail,err: %v\r\n", err)
		log.Errorf("update fail,err: %v", err)
		return
	}
	//关闭当前运行的dcnode
	err = stopDcnodeInDocker()
	if err != nil {
		return
	}
	//删除就版本的dcnode的docker容器
	err = removeDcnodeInDocker()
	if err != nil {
		return
	}
	//运行下载下来的dcnode程序
	err = startDcNode()
	if err != nil {
		return
	}
	fmt.Println("wait new version to get peer secret")
	log.Info("wait new version to get peer secret")
	//等待新版本的dcnode成功获取节点密钥
	_, err = waitNewDcGetPeerSecret()
	if err != nil {
		fmt.Fprintf(os.Stderr, "update fail,err: %v\r\n", err)
		log.Errorf("update fail,err: %v", err)
		return
	}
	log.Infof("new version dcnode  get peer sceret success")
	fmt.Println("new version dcnode  get peer sceret success")
	//更新dcnode的image到配置文件
	config.RunningConfig.NodeImage = programInfo.Url
	//保存配置文件
	if err = config.SaveConfig(config.RunningConfig); err != nil {
		fmt.Fprintf(os.Stderr, "save config fail,err: %v\r\n", err)
		log.Errorf("save config fail,err: %v", err)
		return
	}
	//通过检查version来判断新版本程序是否正常运行
	version, enclaveId, err := getVersionByHttpGet(dcNodeListenPort)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dcnode enclaveid get fail,err: %v\r\n", err)
		log.Errorf("dcnode enclaveid get fail,err: %v", err)
		return
	}
	if version != programInfo.Version {
		fmt.Fprintf(os.Stderr, "dcnode version check fail,version: %s, configedVersion: %s\r\n", version, programInfo.Version)
		log.Errorf("dcnode version check fail,version: %s, configedVersion: %s", version, programInfo.Version)
		return
	}
	if enclaveId != programInfo.EnclaveId {
		fmt.Fprintf(os.Stderr, "dcnode enclaveid check fail,enclaveId: %s, configedEnclaveId: %s\r\n", enclaveId, programInfo.EnclaveId)
		log.Errorf("dcnode enclaveid check fail,enclaveId: %s, configedEnclaveId: %s", enclaveId, programInfo.EnclaveId)
		return
	}
	log.Infof("dcnode upgrade success,version: %s,enclaveid: %s", version, enclaveId)
	fmt.Fprintf(os.Stdout, "dcnode upgrade success,version: %s,enclaveid: %s\r\n", version, enclaveId)
	return
}

//拉取新docker image
func pullDcNodeImage(image string) (err error) {
	//docker pull
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return
	}
	ctx := context.Background()
	//docker pull
	out, err := cli.ImagePull(ctx, image, types.ImagePullOptions{})
	if err != nil {
		return
	}
	defer out.Close()
	//docker pull
	_, err = ioutil.ReadAll(out)
	if err != nil {
		return
	}
	return
}

//删除dcnode的docker容器
func removeDcnodeInDocker() (err error) {
	log.Infof("begin to remove old version dcnode docker container")
	fmt.Println("begin to remove old version dcnode docker container")
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return
	}
	//获取dcnode的docker容器id
	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{All: true})
	if err != nil {
		return
	}
	for _, container := range containers {
		if container.Image == config.RunningConfig.NodeImage {
			log.Infof("begin to remove old version dcnode docker container,container id: %s", container.ID)
			fmt.Printf("begin to remove old version dcnode docker container,container id: %s\r\n", container.ID)
			err = cli.ContainerRemove(context.Background(), container.ID, types.ContainerRemoveOptions{Force: true})
			if err != nil {
				continue
			}
			log.Infof("remove old version dcnode docker container success")
			return
		} else {
			//移除旧版本的dcnode容器
			if strings.Contains(container.Image, "dcnode") {
				log.Infof("begin to remove old version dcnode docker container,container id: %s", container.ID)
				err = cli.ContainerRemove(context.Background(), container.ID, types.ContainerRemoveOptions{Force: true})
				if err != nil {
					continue
				}
				log.Infof("remove old version dcnode docker container success")
				return
			}
			for _, name := range container.Names {
				if name == nodeContainerName {
					log.Infof("begin to remove old version dcnode docker container,container id: %s", container.ID)
					err = cli.ContainerRemove(context.Background(), container.ID, types.ContainerRemoveOptions{Force: true})
					if err != nil {
						continue
					}
					log.Infof("remove old version dcnode docker container success")
					return
				}
			}
		}

	}
	log.Infof("no old version dcnode docker container")
	fmt.Println("no old version dcnode docker container")
	return
}

//通过监听端口来判断程序是否已经运行
func GetPidWithListenPort(listenPort int) (pid int64, err error) {
	cmd := fmt.Sprintf("lsof -i:%d| awk '/LISTEN/ && !/awk/ {print $2}'", listenPort)
	//查看进程是否在运行
	out, err := exec.Command(cmd).Output()
	if err != nil {
		return
	}
	if out == nil {
		err = fmt.Errorf("no process on running")
		return
	}
	pid, err = strconv.ParseInt(string(out), 10, 32)
	return
}

//检查自启动配置是否已经存在
func ifStartupConfiged() bool {
	//查询系统服务，针对当前目录的开机启动服务是否已经配置
	_, err := os.Stat(serviceConfigFile)
	if err != nil { //服务文件已经存在，判断是否指向当前目录
		return false
	}
	p, err := configparser.NewConfigParserFromFile(serviceConfigFile)
	if err != nil {
		return false
	}
	v, err := p.Get("Service", "ExecStart")
	if err != nil {
		return false
	}
	//获取当前目录
	return v == startupShell
}

//判断开机启动是否已经配置
func ifServiceStartupConfiged() bool {
	if !ifStartupConfiged() {
		return false
	}
	servicePath := dcBin + "/dc upgrade auto &"
	//读取startup.sh中的指令，
	file, err := os.Open(startupShell)
	if err != nil {
		log.Fatal(err)
		return false
	}
	defer file.Close()
	space := regexp.MustCompile(`\s+`)
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		s := space.ReplaceAllString(scanner.Text(), " ")
		s = strings.TrimSpace(s)
		if s == servicePath {
			return true
		}
	}
	return false
}

//为服务配置开机启动
func configServiceStartup() bool {
	if !ifStartupConfiged() { //服务没生成，需要进行生成操作
		out, err := os.Create(serviceConfigFile)
		if err != nil {
			log.Fatal(err)
			return false
		}
		defer out.Close()
		w := bufio.NewWriter(out) //创建新的 Writer 对象
		_, err = w.Write([]byte(serviceConfigFileContent))
		if err != nil {
			log.Fatal(err)
			return false
		}
	}
	if ifServiceStartupConfiged() {
		return true
	}
	//未配置重启服务，进行追加
	servicePath := dcBin + "/dc upgrade daemon &"
	file, err := os.OpenFile(startupShell, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Fatal(err)
		return false
	}
	defer file.Close()

	if _, err = file.WriteString(servicePath + "\r\n"); err != nil {
		log.Fatal(err)
		return false
	}
	return true
}

//为某一个服务移除开机启动
func removeServiceStartup() bool {
	if !ifStartupConfiged() { //服务没生成，直接返回true
		return true
	}
	if !ifServiceStartupConfiged() { //原来就没有配置
		return true
	}
	//逐行读取startup.sh中的指令，
	file, err := os.Open(startupShell)
	if err != nil {
		log.Fatal(err)
		return false
	}
	defer file.Close()
	content := ""
	if _, err = file.WriteString(content); err != nil {
		log.Fatal(err)
		return false
	}
	return true
}

//利用docker启动pccs
func runPccsInDocker() (err error) {
	listenPort := 8081
	//查询端口是否已经被占用
	pid, err := GetPidWithListenPort(listenPort)
	if err == nil && pid > 0 { //端口已经启用，请求数据进行测试
		_, gerr := util.HttpGet("https://localhost:8081/sgx/certification/v3/rootcacrl")
		if gerr != nil {
			log.Errorf("Can't start pccs for 8081 port is occupied")
		}
		return
	}
	apiKey := config.RunningConfig.PccsKey
	if len(apiKey) < 32 { //
		return fmt.Errorf("%s is invalid pccs subscription key.For how to subscribe to Intel Provisioning Certificate Service and receive an API key, goto https://api.portal.trustedservices.intel.com/provisioning-certification and click on 'Subscribe'", apiKey)
	}
	apiKeyStr := fmt.Sprintf("APIKEY=%s", apiKey)
	ctx := context.Background()
	dataMount := mount.Mount{
		Type:   mount.TypeVolume,
		Source: pccsVolueName,
		Target: "/opt/intel/pccs",
	}
	hostConfig := &container.HostConfig{
		RestartPolicy: container.RestartPolicy{
			Name: "always",
		},
		NetworkMode: "host",
		Mounts:      []mount.Mount{dataMount},
	}
	cConfig := &container.Config{
		Image: config.RunningConfig.PccsImage,
		Env:   []string{apiKeyStr},
	}
	err = util.StartContainer(ctx, pccsContainerName, cConfig, hostConfig)
	//check if pccs is running
	if err == nil {
		//wait for pccs to start
		time.Sleep(5 * time.Second)
		_, gerr := util.HttpGet("https://localhost:8081/sgx/certification/v3/rootcacrl")
		if gerr != nil {
			log.Errorf("pccs start with err: %v", gerr)
			return gerr
		}
	}
	return
}

//show Container log
func showContainerLog(containerName string) {
	containerId, err := findContainerIdByName(containerName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "find container id error: %v\r\n", err)
		return
	}
	err = showLogsForContainer(containerId)
	if err != nil {
		fmt.Fprintf(os.Stderr, "show logs error: %v\r\n", err)
		return
	}
}

//show container logs in new window
func showLogsOnNewWindowForContainer(containerId string) (err error) {
	cli, _ := client.NewClientWithOpts(client.FromEnv)
	reader, err := cli.ContainerLogs(context.Background(), containerId, types.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Follow: true, Tail: "100"})
	if err != nil {
		return
	}
	defer cli.Close()
	defer reader.Close()
	//创建一个新的窗口
	cmd := exec.Command("cmd", "/c", "start", "docker logs")
	cmd.Stdin = reader
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return err
	}
	handleInterruptSignal()
	return
}

//打印docker中指定容器ID的日志
func showLogsForContainer(containerId string) (err error) {
	cli, _ := client.NewClientWithOpts(client.FromEnv)
	reader, err := cli.ContainerLogs(context.Background(), containerId, types.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Follow: true, Tail: "100"})
	if err != nil {
		return
	}
	defer cli.Close()
	defer reader.Close()
	_, err = io.Copy(os.Stdout, reader)
	if err != nil && err != io.EOF {
		return
	}
	handleInterruptSignal()
	return
}

//find container id by Name
func findContainerIdByName(containerName string) (containerId string, err error) {
	cli, _ := client.NewClientWithOpts(client.FromEnv)
	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{All: true})
	if err != nil {
		return
	}
	for _, container := range containers {
		for _, name := range container.Names {
			if name == "/"+containerName {
				containerId = container.ID
				break
			}
		}
	}
	return
}

//handle interrupt signal
func handleInterruptSignal() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	log.Info("Interrupt signal received, shutting down...")
	os.Exit(0)
}
