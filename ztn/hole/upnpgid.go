package hole

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/fdurand/wireguard-go/ztn/peerconnection"
	"github.com/inverse-inc/packetfence/go/log"
	"github.com/scottjg/upnp"
)

var mapping = new(upnp.Upnp)

var localPort = 1990
var remotePort = 1990

// UPnPGID struct
type UPnPGID struct {
	ConnectionPeer *ExternalConnection
}

// CheckNet search for a gateway
func CheckNet() error {
	err := mapping.SearchGateway()
	return err
}

// ExternalIPAddr return the WAN ip
func ExternalIPAddr() (net.IP, error) {
	err := mapping.ExternalIPAddr()
	if err != nil {
		return nil, err
	}
	return net.ParseIP(mapping.GatewayOutsideIP), nil

}

// NewUPnPGID Init
func NewUPnPGID(ctx context.Context, method string, d *device.Device, logger *device.Logger, myProfile profile.Profile, peerProfile profile.PeerProfile) (Method, error)
	method := UPnPGID{}
	method.Init(context)
	return &method, nil
}

// Init initialyse
func (hole *UPnPGID) Init(context context.Context) {
	log.SetProcessName("wireguard-go")
	ctx := log.LoggerNewContext(context)
	d := &ExternalConnection{
		extAddr: nil,
		ctx:     ctx,
	}
	hole.ExternConn = d
}

// GetExternalInfo fetch wan information
func (hole *UPnPGID) GetExternalInfo(context context.Context) (net.UDPAddr, error) {
	var UDP net.UDPAddr
	err := CheckNet()
	var UDPAddr net.UDPAddr

	if err != nil {
		return UDP, errors.New("your router does not support the UPnP protocol.")
	}

	myExternalIP, err := ExternalIPAddr()
	if err != nil {
		return UDPAddr, err
	}
	hole.ExternConn.extAddr.IP = myExternalIP
	hole.ExternConn.extAddr.Port = remotePort
	AddPortMapping(localPort, remotePort)
	return hole.ExternConn.extAddr, nil
}

// AddPortMapping insert port mapping in the gateway
func AddPortMapping(localPort, remotePort int) bool {
	if err := mapping.AddPortMapping(localPort, remotePort, 60, "UDP", "WireguardGO"); err == nil {
		fmt.Println("Port mapped successfully")
		return true
	}
	fmt.Println("Port failed to map")
	return false
}

// DelPortMapping delete port mapping in the gateway
func DelPortMapping(localPort, remotePort int) {
	mapping.DelPortMapping(remotePort, "UDP")
}

// Run execute the Method
func (hole *UPnPGID) Run(pc *peerconnection.PeerConnection) {

}
