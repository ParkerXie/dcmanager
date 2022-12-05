package blockchain

import (
	"context"
	"fmt"
	"os"
	"time"

	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	"github.com/dcnetio/dc/config"
	logging "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/peer"
)

var log = logging.Logger("dcmanager")

//节点相关程序版本信息
type DcProgram struct {
	Url         string //程序文件下载路径
	EnclaveId   string //程序对应的tee enclaveid
	IdSignature string //委员会对程序对应的tee enclaveid的签名
	Checksum    string //程序的md5校验值
	Version     string //程序版本信息
}

//threaddb的log信息
type Loginfo struct {
	Logid []byte
	Size  uint64
}

type StoreunitInfo struct {
	//文件大小
	Size int64
	//type 文件类型 1:文件 2:threaddb
	Utype uint32
	//备份节点ID列表
	Peers map[string]struct{}
	//拥有该文件的用户列表
	Users map[string]struct{}
	Logs  map[string]uint64 //utype 为2时，存放log文件信息列表
}

//区块链上文件信息存储结构
type BlockStoreunitInfo struct {
	//备份节点ID列表
	Peers []string
	//拥有该文件的用户列表
	Users []types.AccountID
	//文件大小
	Size int64
	//type 文件类型 1:文件 2:threaddb
	Utype uint32
	Logs  []Loginfo
}
type BlockPeerInfo struct { //节点信息
	Req_account   types.AccountID
	Stash         types.AccountID
	Total_space   uint64
	Free_space    uint64
	Status        uint32
	Report_number uint32
	Staked_number uint32 //节点入网请求后的质押时间
	Reward_number uint32
	Ip_address    types.Bytes
}

//从区块链获取最新版本的dc节点程序的信息
func GetConfigedDcNodeInfo() (dcProgram *DcProgram, err error) {
	//随机选择要连接的区块链代理
	var chainApi *gsrpc.SubstrateAPI
	var meta *types.Metadata
	ctx := context.Background()
	//连接区块链
	chainApi, err = gsrpc.NewSubstrateAPI(config.RunningConfig.ChainWsUrl)
	if err != nil {
		log.Errorf("Cann't connect to blockchain,err: %v", err)
	}
	meta, err = chainApi.RPC.State.GetMetadataLatest()
	if err != nil {
		log.Errorf("Cann't get meta from blockchain,err: %v", err)
	}
	//等待区块链同步完成
	log.Info("Wait for blockchain syncing complete")
	waitForChainSyncCompleted(ctx, chainApi, meta)
	log.Info("Blockchain syncing completed")
	//获取当前区块链上的程序版本信息
	dcProgram, err = getProgramInfo(chainApi, meta)
	return
}

//获取当前区块链上的程序版本信息
func getProgramInfo(chainApi *gsrpc.SubstrateAPI, meta *types.Metadata) (*DcProgram, error) {
	key, err := types.CreateStorageKey(meta, "DcNode", "Program")
	if err != nil {
		return nil, err
	}
	var program *DcProgram
	ok, err := chainApi.RPC.State.GetStorageLatest(key, program)
	if err != nil { //区块链报错
		return nil, err
	}
	if !ok {
		err = fmt.Errorf("get Program fail")
		return nil, err
	}
	if program == nil {
		err = fmt.Errorf("get Program fail")
		return nil, err
	}

	return program, nil
}

//等待区块链同步完成
func waitForChainSyncCompleted(ctx context.Context, chainApi *gsrpc.SubstrateAPI, meta *types.Metadata) (err error) {
	health, err := chainApi.RPC.System.Health()
	if err != nil || health.IsSyncing {
		for {
			if err == nil && !health.IsSyncing {
				break
			}
			ticker := time.NewTicker(time.Second)

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				health, err = chainApi.RPC.System.Health()
				if err == nil {
					continue
				}
			}
		}
	}
	return
}

//从区块链获取指定cid的存储位置信息
func GetPeerAddrsForCid(sCid string) (fileSize int64, peerAddrInfos []peer.AddrInfo, err error) {
	//随机选择要连接的区块链代理
	var chainApi *gsrpc.SubstrateAPI
	var meta *types.Metadata
	ctx := context.Background()
	//连接区块链
	chainApi, err = gsrpc.NewSubstrateAPI(config.RunningConfig.ChainWsUrl)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cann't connect to blockchain")
	}
	meta, err = chainApi.RPC.State.GetMetadataLatest()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cann't get meta from blockchain")
	}
	//等待区块链同步完成
	fmt.Println("Wait for blockchain syncing complete")
	waitForChainSyncCompleted(ctx, chainApi, meta)
	fmt.Println("Blockchain syncing completed")
	//提示开始获取存储位置信息
	fmt.Println("Start to get storage location information")
	return getPeerAddrsForCid(sCid, chainApi, meta)
}

//对象状态查询(包括文件和数据库状态)
func getPeerAddrsForCid(sCid string, chainApi *gsrpc.SubstrateAPI, meta *types.Metadata) (fileSize int64, peerAddrInfos []peer.AddrInfo, err error) {
	if chainApi == nil {
		return 0, nil, fmt.Errorf("chain proxy not init")
	}
	if len(sCid) == 0 {
		return 0, nil, fmt.Errorf("invalid key")
	}
	fileIdBytes, _ := codec.Encode([]byte(sCid))
	key, err := types.CreateStorageKey(meta, "DcNode", "Files", fileIdBytes)
	if err != nil {
		return
	}
	var blockStroreunitInfo BlockStoreunitInfo
	ok, err := chainApi.RPC.State.GetStorageLatest(key, &blockStroreunitInfo)
	if err != nil { //区块链报错
		return
	}
	if !ok {
		err = fmt.Errorf("get object fail")
		return
	}
	for _, pid := range blockStroreunitInfo.Peers {
		addrInfo, err := GetPeerAddrInfo(pid, chainApi, meta)
		if err != nil {
			continue
		}
		peerAddrInfos = append(peerAddrInfos, addrInfo)
	}
	fileSize = blockStroreunitInfo.Size
	return
}

//获取节点地址信息
func GetPeerAddrInfo(peerid string, chainApi *gsrpc.SubstrateAPI, meta *types.Metadata) (addrInfo peer.AddrInfo, err error) {
	peerIdBytes, _ := codec.Encode([]byte(peerid))
	// //根据pubkey 取出节点信息
	key, err := types.CreateStorageKey(meta, "DcNode", "Peers", peerIdBytes)
	if err != nil {
		return
	}
	var blockPeerInfo BlockPeerInfo
	ok, err := chainApi.RPC.State.GetStorageLatest(key, &blockPeerInfo)
	if err != nil {
		return
	}
	if !ok {
		return
	}
	pAddrInfo, err := peer.AddrInfoFromString(string(blockPeerInfo.Ip_address))
	if err != nil {
		return
	}
	addrInfo = *pAddrInfo
	return

}
