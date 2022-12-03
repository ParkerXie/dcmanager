package util

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ChainSafe/go-schnorrkel"
	"github.com/cosmos/go-bip39"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
	logging "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
)

func HttpGet(url string, args ...string) ([]byte, error) {
	client := http.Client{Timeout: time.Second}
	if len(args) > 0 {
		url += "?" + strings.Join(args, "&")
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		newStr := buf.String()
		return nil, fmt.Errorf("http get err status,statuscode: %d,errmsg: %v", resp.StatusCode, newStr)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("err occur,no data get")
	}
	return body, nil
}

func HttpGetWithoutCheckCert(url string, args ...string) ([]byte, error) {
	client := http.Client{Timeout: time.Second}
	if len(args) > 0 {
		url += "?" + strings.Join(args, "&")
	}
	//request with out check cert
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		newStr := buf.String()
		return nil, fmt.Errorf("http get err status,statuscode: %d,errmsg: %v", resp.StatusCode, newStr)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("err occur,no data get")
	}
	return body, nil
}

func HttpPost(url string, body []byte) ([]byte, error) {
	client := http.Client{Timeout: time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		newStr := buf.String()
		return nil, fmt.Errorf("http post err status,statuscode: %d,errmsg: %v", resp.StatusCode, newStr)
	}
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("err occur,no data get")
	}
	return body, nil
}

//获取随机非对称加解密私钥
func GetRandomPrivKey() (crypto.PrivKey, error) {
	//生成助记词
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return nil, err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, err
	}
	seed, err := schnorrkel.SeedFromMnemonic(mnemonic, "")
	if err != nil {
		return nil, err
	}
	secret := ed25519.NewKeyFromSeed(seed[:32])
	priv, err := crypto.UnmarshalEd25519PrivateKey([]byte(secret))
	if err != nil {
		return nil, err
	}

	return priv, nil

}

// SetupDefaultLoggingConfig sets up a standard logging configuration.
func SetupDefaultLoggingConfig(file string) error {
	c := logging.Config{
		Format: logging.ColorizedOutput,
		Stderr: true,
		Level:  logging.LevelInfo,
	}
	if file != "" {
		if err := os.MkdirAll(filepath.Dir(file), os.ModePerm); err != nil {
			return err
		}
		c.File = file
	}
	logging.SetupLogging(c)
	return nil
}

func Sha256sum(filepath string) (checksum string, err error) {
	var f *os.File
	f, err = os.Open(filepath)
	if err != nil {
		return
	}
	defer f.Close()
	h := sha256.New()
	_, err = io.Copy(h, f)
	if err != nil {
		return
	}
	checksum = fmt.Sprintf("%x", h.Sum(nil))
	return
}

//create volume
func CreateVolume(ctx context.Context, volumeName string) (v *types.Volume, err error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		log.Fatalf("create docker client fail,err:%v", err)
	}
	volumeList, err := cli.VolumeList(ctx, filters.Args{})
	if err != nil {
		log.Fatalf("list docker volume fail,err:%v", err)
	}
	for _, v = range volumeList.Volumes {
		if v.Name == volumeName {
			return
		}
	}
	newVolume, err := cli.VolumeCreate(ctx, volume.VolumeCreateBody{
		Name: volumeName,
	})
	v = &newVolume
	if err != nil {
		log.Fatalf("create docker volume fail,err:%v", err)
	} else {
		fmt.Printf("create docker volume %s success\n", volumeName)
	}
	return
}

//start container removeOldFlag: true  if exist same name container with different image,remove the old container
func StartContainer(ctx context.Context, containerName string, removeOldFlag bool, config *container.Config, hostConfig *container.HostConfig) (err error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return
	}
	defer cli.Close()
	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{All: true})
	if err != nil {
		return
	}
	createdFlag := false
	containerId := ""
	for _, container := range containers {
		if config.Image == container.Image {
			for _, name := range container.Names {
				if name == "/"+containerName {
					createdFlag = true
					containerId = container.ID
					break
				}
			}
		}
	}
	if !createdFlag { //需要创建
		fmt.Printf("creating %s container ...\n", containerName)
		resp, cerr := cli.ContainerCreate(ctx, config, hostConfig, nil, nil, containerName)
		if cerr != nil {
			//remove container with same name
			if strings.Contains(cerr.Error(), "Conflict. The container name \"/"+containerName+"\" is already in use by container") {
				fmt.Printf("container %s already exists, removing it...\n", containerName)
				if err = cli.ContainerRemove(ctx, containerName, types.ContainerRemoveOptions{Force: true}); err != nil {
					return
				}
				resp, err = cli.ContainerCreate(ctx, config, hostConfig, nil, nil, containerName)
				if err != nil {
					return
				}
			} else {
				err = cerr
				return
			}
		}
		containerId = resp.ID
	}
	execResp, err := cli.ContainerInspect(ctx, containerId)
	if err != nil {
		fmt.Fprintf(os.Stderr, "inspect %s container fail,err: %v\r\n", containerName, err)
		return

	}
	if !execResp.State.Running { // 服务没启动
		fmt.Printf("starting %s  ...\n", containerName)
		if err := cli.ContainerStart(ctx, containerId, types.ContainerStartOptions{}); err != nil {
			fmt.Fprintf(os.Stderr, "start %s fail,err: %v\r\n", containerName, err)
			return err
		}
		fmt.Printf("start %s success\r\n", containerName)
	} else {
		fmt.Printf("%s is running\r\n", containerName)
	}
	return
}

//stop container
func StopContainer(ctx context.Context, containerName string) (err error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return
	}
	defer cli.Close()
	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		return
	}
	containerId := ""
	for _, container := range containers {
		for _, name := range container.Names {
			if name == "/"+containerName {
				containerId = container.ID
				break
			}
		}
	}
	if containerId != "" {
		fmt.Printf("stopping %s  ...\r\n", containerName)
		if err = cli.ContainerStop(ctx, containerId, nil); err != nil {
			fmt.Fprintf(os.Stderr, "stop %s  fail,err: %v\r\n", containerName, err)
			return
		}
	} else {
		fmt.Printf("%s  is not running\r\n", containerName)
	}
	return
}

//生成随机字符串
func RandStringBytes(n int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
