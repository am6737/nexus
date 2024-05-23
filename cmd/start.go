package cmd

import (
	"fmt"
	"github.com/sevlyar/go-daemon"
	"github.com/urfave/cli/v2"
	"log"
	"os"
)

func start(c *cli.Context) error {
	// todo 找地方扔日志文件
	// 日志保存到目录
	_, err := deamonize(c)
	if err != nil {
		fmt.Println("start error:", err)
		return err
	}

	return nil
}

func deamonize(c *cli.Context) (*os.Process, error) {
	cntxt := &daemon.Context{
		PidFileName: "sample.pid",
		PidFilePerm: 0644,
		LogFileName: "sample.log",
		LogFilePerm: 0640,
		WorkDir:     "./",
		Umask:       027,
	}

	d, err := cntxt.Reborn()
	if err != nil {
		log.Fatal("Unable to run: ", err)
	}

	if d != nil {
		return nil, nil
	}
	defer cntxt.Release()

	err = run(c)
	if err != nil {
		return nil, err
	}
	return d, nil
}
