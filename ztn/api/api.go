package api

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/inverse-inc/packetfence/go/unifiedapiclient"
	"github.com/inverse-inc/packetfence/go/unifiedapiclient/glpclient"
	"golang.org/x/crypto/ssh/terminal"
)

var APIClient *unifiedapiclient.Client
var APIClientCtx context.Context

// TODO: replace with prompts or configuration
func SetupAPIClient() {
	server := sharedutils.EnvOrDefault("WG_SERVER", "")
	if server == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Server: ")
		server, _ = reader.ReadString('\n')
		server = strings.Trim(server, "\r\n")
	} else {
		fmt.Println("Using environment provided server:", server)
	}

	port := sharedutils.EnvOrDefault("WG_SERVER_PORT", "")
	if port == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Server port (default 9999): ")
		port, _ = reader.ReadString('\n')
		port = strings.Trim(port, "\r\n")

		if port == "" {
			port = "9999"
		}
	} else {
		fmt.Println("Using environment provided server port:", port)
	}

	verifySslStr := sharedutils.EnvOrDefault("WG_SERVER_VERIFY_TLS", "")
	verifySsl := true
	if verifySslStr == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Verify TLS identity of server? (Y/n): ")
		verifySslStr, _ = reader.ReadString('\n')
		verifySslStr = strings.Trim(verifySslStr, "\r\n")
	} else {
		fmt.Println("Using environment provided server verify TLS:", verifySslStr)
	}

	if verifySslStr == "" {
		verifySsl = true
	} else {
		verifySslStr = strings.TrimSpace(verifySslStr)
		verifySslStr = strings.ToLower(verifySslStr)
		verifySsl = (verifySslStr == "y" || verifySslStr == "yes")
	}

	username := sharedutils.EnvOrDefault("WG_USERNAME", "")
	if username == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Username: ")
		username, _ = reader.ReadString('\n')
		username = strings.Trim(username, "\r\n")
	} else {
		fmt.Println("Using environment provided username:", username)
	}

	fmt.Print("Enter Password for " + username + ": ")
	bytePassword, _ := terminal.ReadPassword(0)
	password := string(bytePassword)

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifySsl},
		},
	}
	unifiedapiclient.SetHTTPClient(httpClient)

	APIClientCtx = context.Background()
	APIClient = unifiedapiclient.New(APIClientCtx, username, password, "https", server, port)
}

func GetAPIClient() *unifiedapiclient.Client {
	if APIClient == nil {
		SetupAPIClient()
	}
	return APIClient
}

type Event struct {
	Type string `json:"type"`
	Data gin.H  `json:"data"`
}

func init() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
}

func GLPPublish(category string, e Event) error {
	err := GetAPIClient().CallWithBody(APIClientCtx, "POST", "/api/v1/remote_clients/events/"+category, e, &unifiedapiclient.DummyReply{})
	return err
}

func GLPClient(category string) *glpclient.Client {
	apiClient := GetAPIClient()
	c := glpclient.NewClient(apiClient, "/api/v1/remote_clients/events", category)
	c.LoggingEnabled = sharedutils.EnvOrDefault("LOG_LEVEL", "") == "debug"
	return c
}

func GLPPrivateClient(priv, pub, serverPub [32]byte) *glpclient.Client {
	apiClient := GetAPIClient()
	c := glpclient.NewClient(apiClient, "/api/v1/remote_clients/my_events", "")
	c.LoggingEnabled = sharedutils.EnvOrDefault("LOG_LEVEL", "") == "debug"
	c.SetPrivateMode(priv, pub, serverPub)
	return c
}
