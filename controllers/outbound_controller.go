package controllers

import "fmt"

// OutboundController 出站控制器 必须实现 interfaces.OutboundController 接口
type OutboundController struct {
	// 可以添加其他字段
}

// Send 发送数据到目标地址
func (oc *OutboundController) Send(data []byte, destAddr string) error {
	// 执行数据加密、封装等操作
	fmt.Println("Sending data to", destAddr)
	// 模拟发送数据
	return nil
}

func (oc *OutboundController) Listen() {
	//TODO implement me
	panic("implement me")
}
