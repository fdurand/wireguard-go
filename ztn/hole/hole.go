package hole

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

var localWGIP = net.ParseIP("127.0.0.1")

const localWGPort = 6969

// ExternalConnection struct
type ExternalConnection struct {
	myID        string
	PeerID      string
	MyProfile   profile.Profile
	PeerProfile profile.PeerProfile

	WgConn        *net.UDPConn
	LocalPeerConn *net.UDPConn
	Device        *device.Device
	Logger        *device.Logger

	MyAddr   *net.UDPAddr
	PeerAddr *net.UDPAddr

	Started       bool
	Connected     bool
	LastKeepalive time.Time

	TriedPrivate bool
}

// Method interface
type Method interface {
	GetExternalInfo(ctx context.Context) (net.UDPAddr, error)
	Run()
	Init(context context.Context)
}

// Creater function
type Creater func(context.Context) (Method, error)

var methodLookup = map[string]Creater{
	"stun":    NewSTUN,
	"upnpgid": NewUPnPGID,
}

// Create function
func Create(ctx context.Context, method string, d *device.Device, logger *device.Logger, myProfile profile.Profile, peerProfile profile.PeerProfile) (Method, error) {
	if creater, found := methodLookup[method]; found {
		return creater(ctx)
	}

	return nil, fmt.Errorf("Method of %s not found", method)
}
