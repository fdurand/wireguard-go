package hole

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/inverse-inc/packetfence/go/log"
	"github.com/scottjg/upnp"
)

var mapping = new(upnp.Upnp)

var localPort = 1990
var remotePort = 1990

// UPnPGID struct
type UPnPGID struct {
	ExternConn *ExternalConnection
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
		return err, nil
	}
	return nil, net.ParseIP(mapping.GatewayOutsideIP)

}

// NewUPnPGID Init
func NewUPnPGID(context context.Context) (Method, error) {
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
func (hole *UPnPGID) GetExternalInfo() (net.UDPAddr, error) {
	var UDP net.UDPAddr
	err := CheckNet()
	var UDPAddr net.UDPAddr

	if err != nil {
		return UDP, errors.New("your router does not support the UPnP protocol.")
	}

	myExternalIP, err := ExternalIPAddr()
	if err != nil {
		return err, UDPAddr
	}
	hole.ExternConn.extAddr.IP = myExternalIP
	hole.ExternConn.extAddr.Port = remotePort
	AddPortMapping(localPort, remotePort)
	return nil, hole.ExternConn.extAddr
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
func (hole *UPnPGID) Run() {

}
