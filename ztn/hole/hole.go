package hole

import (
	"context"
	"fmt"
	"net"

	"github.com/fdurand/wireguard-go/ztn/peerconnection"
)

var localWGIP = net.ParseIP("127.0.0.1")

const localWGPort = 6969

// ExternalConnection struct
type ExternalConnection struct {
	extAddr *net.UDPAddr
	ctx     context.Context
}

// Method interface
type Method interface {
	GetExternalInfo(ctx context.Context) (net.UDPAddr, error)
	Run(pc *peerconnection.PeerConnection)
	Init(context context.Context)
}

// Creater function
type Creater func(context.Context) (Method, error)

var methodLookup = map[string]Creater{
	"stun":    NewSTUN,
	"upnpgid": NewUPnPGID,
}

// Create function
func Create(ctx context.Context, method string) (Method, error) {
	if creater, found := methodLookup[method]; found {
		return creater(ctx)
	}

	return nil, fmt.Errorf("Method of %s not found", method)
}
