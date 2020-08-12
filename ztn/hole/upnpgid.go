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

func CheckNet() error {
	err := mapping.SearchGateway()
	return err
}

func ExternalIPAddr() (error, net.IP) {
	err := mapping.ExternalIPAddr()
	if err != nil {
		return err, nil
	}
	return nil, net.ParseIP(mapping.GatewayOutsideIP)

}

// NewUPnPGID
func NewUPnPGID(context context.Context) (Method, error) {
	method := UPnPGID{}
	method.Init(context)
	return &method, nil
}

func (hole *UPnPGID) Init(context context.Context) {
	log.SetProcessName("wireguard-go")
	ctx := log.LoggerNewContext(context)
	d := &ExternalConnection{
		extAddr: nil,
		ctx:     ctx,
	}
	hole.ExternConn = d
}

func (hole *UPnPGID) GetExternalInfo() (error, net.UDPAddr) {
	var UDP net.UDPAddr
	err := CheckNet()
	var UDPAddr net.UDPAddr

	if err != nil {
		return errors.New("Your router does not support the UPnP protocol."), UDP
	}

	err, myExternalIP := ExternalIPAddr()
	if err != nil {
		return err, UDPAddr
	}
	hole.ExternConn.extAddr.IP = myExternalIP
	hole.ExternConn.extAddr.Port = remotePort
	AddPortMapping(localPort, remotePort)
	return nil, hole.ExternConn.extAddr
}

func AddPortMapping(localPort, remotePort int) bool {
	if err := mapping.AddPortMapping(localPort, remotePort, 60, "UDP", "WireguardGO"); err == nil {
		fmt.Println("Port mapped successfully")
		return true
	} else {
		fmt.Println("Port failed to map")
		return false
	}
}

func DelPortMapping(localPort, remotePort int) {
	mapping.DelPortMapping(remotePort, "UDP")
}

func (hole *UPnPGID) Run() {

}
