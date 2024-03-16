package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	// 主要为了降低 GC 压力
	bytesPool = sync.Pool{
		New: func() interface{} {
			var buffer = bytes.NewBuffer(make([]byte, 2048))
			return buffer
		},
	}
)

func NewBufferFromPool() *bytes.Buffer {
	return bytesPool.Get().(*bytes.Buffer) // 通过Get来获得一个
}
func main() {
	l, err := net.Listen("tcp4", ":10800")
	if err != nil {
		log.Print(err)
		return
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Print(err)
			continue
		}
		var method = make([]byte, 20)
		var path = make([]byte, 2048)
		var protocol = make([]byte, 10)
		_, err = fmt.Fscanf(conn, "%s%s%s", &method, &path, &protocol)
		if err != nil {
			log.Print(err)
			continue
		}
		firstLine := fmt.Sprintf("%s %s %s", string(method), string(path), string(protocol))
		log.Print(firstLine)
		targetHost, targetPort := parseHost(string(path))
		go proxy(conn, targetHost, targetPort, firstLine, string(method))
	}
}
func parseHost(path string) (string, string) {
	if !strings.HasPrefix(path, "http") {
		hostPath := strings.Split(path, ":")
		return hostPath[0], hostPath[1]
	}
	re := regexp.MustCompile("/+")
	hostPath := re.Split(path, -1)[1]
	tmp := strings.Split(hostPath, ":")
	if len(tmp) < 2 {
		return tmp[0], "80"
	}
	return tmp[0], tmp[1]
}
func proxy(conn net.Conn, host string, port string, firstLine string, method string) {
	s, err := net.DialTimeout("tcp4", fmt.Sprintf("%s:%s", host, port), time.Duration(1)*time.Second)
	if err != nil {
		log.Print(err)
		return
	}
	if method != "CONNECT" {
		s.Write([]byte(firstLine))
	} else {
		var buffer = make([]byte, 1024)
		_, err := conn.Read(buffer)
		if err != nil {
			log.Print(err)
		}
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n"))
		conn.Write([]byte("Proxy-agent: golang\r\n"))
		conn.Write([]byte("\r\n"))
	}
	var clientBuffer = NewBufferFromPool().Bytes()
	var serverBuffer = NewBufferFromPool().Bytes()
	go func() {
		defer s.Close()
		defer log.Printf("%s finished", firstLine)
		var n int
		for {
			n, err = s.Read(serverBuffer)
			if err == io.EOF {
				break
			}
			if n == 0 {
				time.Sleep(time.Millisecond * time.Duration(100))
				continue
			}
			conn.Write(serverBuffer[:n])
		}
	}()
	go func() {
		defer conn.Close()
		var n int
		for {
			n, err = conn.Read(clientBuffer)
			if err == io.EOF {
				break
			}
			if n == 0 {
				time.Sleep(time.Millisecond * time.Duration(100))
				continue
			}
			s.Write(clientBuffer[:n])
		}
	}()
}
