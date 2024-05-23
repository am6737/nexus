package cmd

import (
	"fmt"
	"github.com/urfave/cli/v2"
	"io/ioutil"
	"os"
	"strconv"
	"syscall"
)

func stop(c *cli.Context) error {
	pidFile := "sample.pid"

	// 读取 pid 文件
	pidData, err := ioutil.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("unable to read pid file: %v", err)
	}

	// 解析 pid
	pid, err := strconv.Atoi(string(pidData))
	if err != nil {
		return fmt.Errorf("unable to parse pid: %v", err)
	}

	// 停止进程
	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("unable to find process: %v", err)
	}

	err = process.Signal(syscall.SIGTERM)
	if err != nil {
		return fmt.Errorf("unable to signal process: %v", err)
	}

	fmt.Printf("Process with PID %d has been stopped\n", pid)
	return nil
}
