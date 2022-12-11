package util

//从ipfs网络中下载文件

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dariubs/percent"
	sym "github.com/dcnetio/gothreads-lib/crypto/symmetric"
	gproto "github.com/gogo/protobuf/proto"
	ipfslite "github.com/hsanjuan/ipfs-lite"
	"github.com/ipfs/go-cid"
	ipld "github.com/ipfs/go-ipld-format"
	logging "github.com/ipfs/go-log/v2"
	"github.com/ipfs/go-merkledag"
	"github.com/ipfs/go-mfs"
	ufsio "github.com/ipfs/go-unixfs/io"
	pb "github.com/ipfs/go-unixfs/pb"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

const dcFileHead = "$$dcfile$$"
const (
	FileDealStatusSuccess = iota
	FileDealStatusToIpfs
	FileDealStatusTransmit
	FileDealStatusFail
	FileDealStatusErr
)

var log = logging.Logger("dcmanager")

type FileTransmit interface {
	//FileDealStatus 0:成功 1:转化为ipfs对象操作中 2:文件传输中 3:传输失败 4:异常
	UpdateTransmitSize(status int, size uint64)
}

type TransmitObj struct {
	TotalSize uint64
}

func (tObj *TransmitObj) UpdateTransmitSize(status int, size uint64) {
	if tObj.TotalSize > 0 { //显示下载百分比与大小
		fmt.Printf("\r%s", strings.Repeat(" ", 50))
		downloadPercent := percent.PercentOf(int(size), int(tObj.TotalSize))
		fmt.Printf("\rDownloading... %.2f%% complete, downloaded/totalsize: %d/%d   ", downloadPercent, size, tObj.TotalSize)
	} else { //只显示下载大小
		fmt.Printf("\r%s", strings.Repeat(" ", 50))
		fmt.Printf("\rDownloading... %d complete ", size)
	}
}

// DownloadFromIpfs 根据cid从网络中拉取文件或文件夹到本地
func DownloadFromIpfs(fcid, secret, savePath string, addrInfos []peer.AddrInfo, timeout time.Duration, fileTransmit FileTransmit) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	if timeout == 0 {
		cancel()
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()
	ds := ipfslite.NewInMemoryDatastore()
	hostKey, _, err := newIPFSHostKey()
	if err != nil {
		return
	}
	port, err := GetAvailablePort()
	if err != nil {
		return
	}
	hostAddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port))
	if err != nil {
		return err
	}
	h, dht, err := ipfslite.SetupLibp2p(
		ctx,
		hostKey,
		nil,
		[]multiaddr.Multiaddr{hostAddr},
		ds,
		ipfslite.Libp2pOptionsExtra...,
	)

	if err != nil {
		panic(err)
	}

	lite, err := ipfslite.New(ctx, ds, nil, h, dht, nil)
	if err != nil {
		panic(err)
	}
	lite.Bootstrap(addrInfos)

	c, _ := cid.Decode(fcid)
	ioReader, err := lite.GetFile(ctx, c)
	if err != nil {
		if errors.Is(err, ufsio.ErrIsDir) { //是文件夹，下载文件夹
			err := pullAndDownloadFolder(ctx, lite, c, savePath, secret, fileTransmit)
			if err != nil {
				return err
			}
			return nil
		} else {
			return err
		}
	}
	defer ioReader.Close()
	err = downloadFile(ctx, ioReader, savePath, secret, fileTransmit)
	return

}

// DownloadFile 下载文件
func downloadFile(ctx context.Context, ioReader ufsio.ReadSeekCloser, savePath string, secret string, fileTransmit FileTransmit) error {
	//判断文件是否存在
	_, err := os.Stat(savePath) //判断文件是否存在
	if err == nil {             //文件存在
		return nil
	}
	if ioReader == nil {
		return fmt.Errorf("ioReader is nil")
	}
	//文件不存在，需要下载
	var symKey *sym.Key
	if secret != "" {
		symKey, _ = sym.FromString(secret)
	}
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	rp, wp := io.Pipe()
	wg.Add(1)
	go func() { //读取数据
		defer wp.Close()
		var readSize uint64 = 0
		waitBuffer := []byte{} //引入缓存主要防止一次没读满就返回，导致解密不成功情况
		buf := make([]byte, 1052)
		headDealFlag := false
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			n, rerr := ioReader.Read(buf)
			if n > 0 {
				waitBuffer = append(waitBuffer, buf[:n]...)
				if readSize == 0 && !headDealFlag {
					if len(waitBuffer) < 32 {
						continue
					} else { //判断是否是dc网络存储的文件头
						headDealFlag = true
						if bytes.Equal([]byte(dcFileHead), waitBuffer[0:10]) { //是dc网络存储的文件，需要去掉32字节附加头（dc文件标志与用户pubkey hash值组合）
							waitBuffer = waitBuffer[32:]
						}
					}
				}
				if len(waitBuffer) < 1052 {
					continue
				}
				content := waitBuffer[:1052]
				waitBuffer = waitBuffer[1052:]
				if symKey != nil { //需要进行解密处理
					content, err = symKey.Decrypt(content)
					if err != nil {
						return
					}
				}
				readSize += (uint64)(n) //累计读取文件大小
				_, werr := wp.Write(content)
				if werr != nil {
					return

				}

			} else if rerr != nil { //
				if len(waitBuffer) > 0 { //判断是否缓冲区还有数据没写完整
					wp.Write(waitBuffer)
				}
				return
			}

		}
	}()
	go func() { //添加数据到本地
		defer rp.Close()
		defer wg.Done()

		f, err := os.Create(savePath) //创建文件
		if err != nil {
			return
		}
		w := bufio.NewWriter(f) //创建新的 Writer 对象
		defer w.Flush()
		var dealedSize uint64 = 0
		buf := make([]byte, 1024)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			n, rerr := rp.Read(buf)
			if n > 0 {
				content := buf[:n]
				if dealedSize == 0 && n > 32 { //移除pubkey hash头
					content = content[32:]
				}
				//将content写入文件
				wn, err := w.Write(content)
				if err != nil {
					return
				}
				dealedSize += (uint64)(wn) //累计写入的文件大小
				if fileTransmit != nil {
					fileTransmit.UpdateTransmitSize(FileDealStatusTransmit, dealedSize+32)
				}
			} else {
				if rerr != nil { //文件下载完成
					fileTransmit.UpdateTransmitSize(FileDealStatusSuccess, dealedSize+32)
					return
				}
			}
		}
	}()
	wg.Wait()
	return nil

}

// pullAndDownloadFolder 根据cid从网络中拉取文件夹下所有文件到本地
func pullAndDownloadFolder(ctx context.Context, p *ipfslite.Peer, c cid.Cid, savePath string, secret string, fileTransmit FileTransmit) error {
	v := new(merkledag.ProgressTracker)
	pCtx := v.DeriveContext(ctx)
	fetchResChan := make(chan struct{})
	top := merkledag.NodeWithData(folderPBData([]byte(c.String())))
	top.SetLinks([]*ipld.Link{
		{
			Name: "root",
			Cid:  c,
		},
	})
	rt, err := mfs.NewRoot(pCtx, p.DAGService, top, nil)
	if err != nil {
		return err
	}
	// get this dir
	topi, err := rt.GetDirectory().Child("root")
	if err != nil {
		return err
	}

	//make dir
	err = os.MkdirAll(savePath, os.ModePerm)
	if err != nil {
		return err
	}
	// get all files
	go func() {
		defer close(fetchResChan)
		err = downloadFolderFromIpfs(pCtx, p, topi.(*mfs.Directory), savePath, secret, fileTransmit)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-fetchResChan:
		return nil
	}
}

//downloadFolderFromIpfs 根据cid从网络中拉取文件夹下所有文件到本地
func downloadFolderFromIpfs(ctx context.Context, p *ipfslite.Peer, dir *mfs.Directory, savePath string, secret string, fileTransmit FileTransmit) error {
	err := dir.ForEachEntry(ctx, func(nl mfs.NodeListing) error {
		if nl.Type == int(mfs.TFile) {
			// get file
			fid, err := cid.Decode(nl.Hash)
			if err != nil {
				return err
			}
			ioReader, err := p.GetFile(ctx, fid)
			if err != nil {
				return err
			}
			defer ioReader.Close()
			err = downloadFile(ctx, ioReader, filepath.Join(savePath, nl.Name), secret, fileTransmit)
			if err != nil {
				return err
			}
		} else {
			subDir, err := dir.Child(nl.Name)
			if err != nil {
				return err
			}
			//mkdir
			dirPath := filepath.Join(savePath, nl.Name)
			err = os.MkdirAll(dirPath, os.ModePerm)
			if err != nil {
				return err
			}
			err = downloadFolderFromIpfs(ctx, p, subDir.(*mfs.Directory), dirPath, secret, fileTransmit)
		}
		return nil
	})
	return err
}

//FolderPBData returns Bytes that represent a Directory.
func folderPBData(pathData []byte) []byte {
	pbfile := new(pb.Data)
	typ := pb.Data_Directory
	pbfile.Type = &typ
	pbfile.Data = pathData

	data, err := gproto.Marshal(pbfile)
	if err != nil {
		//this really shouldnt happen, i promise
		panic(err)
	}
	return data
}

// 获取可用端口
func GetAvailablePort() (int, error) {
	address, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("0.0.0.0:%d", 0))
	if err != nil {
		return 0, err
	}
	listener, err := net.ListenTCP("tcp", address)
	if err != nil {
		address, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:0", "0.0.0.0"))
		if err != nil {
			return 0, err
		}

		listener, err = net.ListenTCP("tcp", address)
		if err != nil {
			return 0, err
		}
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func newIPFSHostKey() (crypto.PrivKey, []byte, error) {
	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, 0)
	if err != nil {
		return nil, nil, err
	}
	key, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	return priv, key, nil
}
