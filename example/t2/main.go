package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"
)

type T struct {
}

func (*T) run(now time.Time) {
	fmt.Println("run executed at", now)
	time.Sleep(time.Second * 10)
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 创建一个计时器，每隔 100 毫秒触发一次
	clockSource := time.NewTicker(time.Millisecond * 100)
	defer clockSource.Stop()

	t := &T{}

	// 模拟处理时间较短的任务
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-clockSource.C:
				fmt.Println(1)
				t.run(now)
				fmt.Println(2)
			}
		}
	}()

	// 监听信号，收到信号后取消上下文，退出程序
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	<-sigChan
	cancel()
}
