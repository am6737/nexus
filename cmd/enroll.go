package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/am6737/nexus/config"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net/http"
)

var enrollResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		Online     bool   `json:"online"`
		EnrollAt   int64  `json:"enroll_at"`
		HostId     string `json:"host_id"`
		LastSeenAt string `json:"last_seen_at"`
		Config     string `json:"config"`
	} `json:"data"`
}

func enroll(c *cli.Context) error {
	code := c.String("code")
	if code == "" {
		return fmt.Errorf("缺少注册代码")
	}

	server := c.String("server")
	if server == "" {
		return fmt.Errorf("缺少服务器地址")
	}

	url := fmt.Sprintf("http://%s/api/v1/hosts/enroll/%s", server, code)
	response, err := sendPostRequest(url, nil, "")
	if err != nil {
		return fmt.Errorf("enrollment failed: %v", err)
	}
	err = json.Unmarshal([]byte(response), &enrollResponse)
	if err != nil {
		return fmt.Errorf("could not parse response: %v", err)
	}

	if enrollResponse.Code != http.StatusOK {
		return fmt.Errorf("enrollment failed: %s", enrollResponse.Msg)
	}

	fmt.Println("enrollResponse.Data.Config => ", enrollResponse.Data.Config)

	var yamlData config.Config
	if err := yaml.Unmarshal([]byte(enrollResponse.Data.Config), &yamlData); err != nil {
		fmt.Println("Error:", err)
		return err
	}

	// 将格式化后的 JSON 数据转换为 YAML
	yamlBytes, err := yaml.Marshal(yamlData)
	if err != nil {
		return fmt.Errorf("could not convert JSON to YAML: %v", err)
	}

	fmt.Println(string(yamlBytes))

	if err = ioutil.WriteFile("config.yaml", yamlBytes, 0644); err != nil {
		return fmt.Errorf("could not write config to file: %v", err)
	}

	return nil
}

func sendPostRequest(url string, body []byte, token string) (string, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf("could not create request: %v", err)
	}

	// Add Bearer token if provided
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad response: %s", resp.Status)
	}

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("could not read response body: %v", err)
	}

	return string(responseBody), nil
}
