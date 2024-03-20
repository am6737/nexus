package controllers

import (
	"context"
	"errors"
	"github.com/am6737/nexus/api"
	"github.com/am6737/nexus/host"
	"log"
	"sync"
	"time"
)

var (
	QueryTimeout   = 2 * time.Second
	UpdateInterval = 30 * time.Second
)

type LighthouseController struct {
	mu          sync.RWMutex
	hosts       map[api.VpnIp]*host.HostInfo
	queryQueue  chan api.VpnIp
	queryWorker *sync.WaitGroup
}

func NewLighthouseController() *LighthouseController {
	return &LighthouseController{
		hosts:       make(map[api.VpnIp]*host.HostInfo),
		queryQueue:  make(chan api.VpnIp, 1000),
		queryWorker: &sync.WaitGroup{},
	}
}

func (lc *LighthouseController) Start(ctx context.Context) error {
	log.Println("LighthouseController started successfully")
	// 启动定时任务，定期发送节点更新通知
	go lc.startUpdateWorker(ctx)
	// 启动查询处理工作人员
	go lc.startQueryWorker(ctx)
	return nil
}

func (lc *LighthouseController) startUpdateWorker(ctx context.Context) {
	ticker := time.NewTicker(UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			//lc.SendUpdate()
		}
	}
}

func (lc *LighthouseController) startQueryWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case vpnIP := <-lc.queryQueue:
			lc.queryWorker.Add(1)
			go func(vpnIP api.VpnIp) {
				defer lc.queryWorker.Done()
				lc.processQuery(vpnIP)
			}(vpnIP)
		}
	}
}

func (lc *LighthouseController) Query(vpnIP api.VpnIp) (*host.HostInfo, error) {
	if host, ok := lc.hosts[vpnIP]; ok {
		return host, nil
	}
	lc.queryQueue <- vpnIP
	return nil, nil
}

func (lc *LighthouseController) processQuery(vpnIP api.VpnIp) {
	// 发送查询消息到其他节点
	//queryMsg := NewQueryMessage(vpnIP)
	//response, err := lc.sendQueryToLighthouses(queryMsg)
	//if err != nil {
	//	log.Printf("Query failed for VPN IP %s: %v\n", vpnIP, err)
	//	return
	//}
	//
	//// 解析响应消息
	//info, err := ParseQueryResponse(response)
	//if err != nil {
	//	log.Printf("Failed to parse query response for VPN IP %s: %v\n", vpnIP, err)
	//	return
	//}
	//
	//// 存储查询结果
	//if err := lc.Store(info); err != nil {
	//	log.Printf("Failed to store query response for VPN IP %s: %v\n", vpnIP, err)
	//}
}

func (lc *LighthouseController) Store(info *host.HostInfo) error {
	if info == nil {
		return errors.New("nil node info")
	}

	lc.mu.Lock()
	defer lc.mu.Unlock()

	lc.hosts[info.VpnIp] = info
	log.Printf("Node stored successfully: %+v\n", info)
	return nil
}

// 其他方法保持不变
