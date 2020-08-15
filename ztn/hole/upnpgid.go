package hole

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/fdurand/wireguard-go/device"
	"github.com/fdurand/wireguard-go/ztn/api"
	"github.com/fdurand/wireguard-go/ztn/bufferpool"
	"github.com/fdurand/wireguard-go/ztn/config"
	"github.com/fdurand/wireguard-go/ztn/constants"
	"github.com/fdurand/wireguard-go/ztn/profile"
	"github.com/fdurand/wireguard-go/ztn/util"
	"github.com/inverse-inc/packetfence/go/log"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"github.com/scottjg/upnp"
)

var mapping = new(upnp.Upnp)

var localPort = constants.LocalWGPort
var remotePort = constants.LocalWGPort

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
func NewUPnPGID(ctx context.Context, d *device.Device, logger *device.Logger, myProfile profile.Profile, peerProfile profile.PeerProfile) (Method, error) {
	method := UPnPGID{}
	method.init(ctx, d, logger, myProfile, peerProfile)
	return &method, nil
}

// Init initialyse
func (hole *UPnPGID) init(context context.Context, d *device.Device, logger *device.Logger, myProfile profile.Profile, peerProfile profile.PeerProfile) {
	log.SetProcessName("wireguard-go")
	ctx := log.LoggerNewContext(context)
	e := &ExternalConnection{
		Device:      d,
		Logger:      logger,
		myID:        myProfile.PublicKey,
		PeerID:      peerProfile.PublicKey,
		MyProfile:   myProfile,
		PeerProfile: peerProfile,
		Ctx:         ctx,
	}
	hole.ConnectionPeer = e
}

// GetExternalInfo fetch wan information
func (hole *UPnPGID) GetExternalInfo() error {
	err := CheckNet()
	if err != nil {
		return errors.New("your router does not support the UPnP protocol.")
	}

	myExternalIP, err := ExternalIPAddr()
	if err != nil {
		return err
	}
	MyUDP := &net.UDPAddr{IP: myExternalIP, Port: remotePort}
	hole.ConnectionPeer.MyAddr = MyUDP
	err = hole.AddPortMapping(localPort, remotePort)
	if err != nil {
		return errors.New("Fail to add the port mapping")
	}
	return nil
}

// AddPortMapping insert port mapping in the gateway
func (hole *UPnPGID) AddPortMapping(localPort, remotePort int) error {
	if err := mapping.AddPortMapping(localPort, remotePort, 60, "UDP", "WireguardGO"); err == nil {
		fmt.Println("Port mapped successfully")
		hole.ConnectionPeer.Logger.Info.Print("Port mapped successfully")
		return nil
	}
	return errors.New("Fail to add the port mapping")
}

// DelPortMapping delete port mapping in the gateway
func DelPortMapping(localPort, remotePort int) {
	mapping.DelPortMapping(remotePort, "UDP")
}

// Run execute the Method
func (hole *UPnPGID) Start() error {
	var err error
	err = hole.GetExternalInfo()

	// if err != nil {
	// 	return err
	// }

	// hole.ConnectionPeer.WgConn, err = net.DialUDP("udp4", nil, &net.UDPAddr{IP: constants.LocalWGIP, Port: constants.LocalWGPort})
	// sharedutils.CheckError(err)

	hole.ConnectionPeer.LocalPeerConn, err = net.ListenUDP(udp, nil)
	sharedutils.CheckError(err)

	hole.ConnectionPeer.Logger.Debug.Printf("Listening on %s for peer %s\n", hole.ConnectionPeer.LocalPeerConn.LocalAddr(), hole.ConnectionPeer.PeerID)

	messageChan := make(chan *pkt)
	hole.ConnectionPeer.Listen(hole.ConnectionPeer.LocalPeerConn, messageChan)
	// hole.ConnectionPeer.Listen(hole.ConnectionPeer.WgConn, messageChan)
	var peerAddrChan <-chan string
	keepalive := time.Tick(500 * time.Millisecond)
	keepaliveMsg := pingMsg

	foundPeer := make(chan bool)

	a := strings.Split(hole.ConnectionPeer.LocalPeerConn.LocalAddr().String(), ":")
	var localPeerAddr = fmt.Sprintf("%s:%s", constants.LocalWGIP.String(), a[len(a)-1])
	// var localWGAddr = fmt.Sprintf("%s:%d", constants.LocalWGIP.String(), constants.LocalWGPort)

	for {
		res := func() bool {
			var message *pkt
			// var ok bool

			defer func() {
				if message != nil {
					bufferpool.DefaultBufferPool.Put(message.message)
				}
			}()

			select {
			// case message, ok = <-messageChan:
			// 	if !ok {
			// 		return false
			// 	}

			// 	switch {

			// 	case string(message.message) == pingMsg:
			// 		hole.ConnectionPeer.Logger.Debug.Println("Received ping from", hole.ConnectionPeer.PeerAddr)
			// 		hole.ConnectionPeer.LastKeepalive = time.Now()
			// 		hole.ConnectionPeer.Connected = true

			// 	default:
			// 		if message.raddr.String() == localWGAddr {
			// 			n := len(message.message)
			// 			hole.ConnectionPeer.Logger.Debug.Printf("send to WG server: [%s]: %d bytes\n", hole.ConnectionPeer.PeerAddr, n)
			// 			util.UdpSend(message.message, hole.ConnectionPeer.LocalPeerConn, hole.ConnectionPeer.PeerAddr)
			// 		} else {
			// 			n := len(message.message)
			// 			hole.ConnectionPeer.Logger.Debug.Printf("send to WG server: [%s]: %d bytes\n", hole.ConnectionPeer.WgConn.RemoteAddr(), n)
			// 			hole.ConnectionPeer.WgConn.Write(message.message)
			// 		}

			// 	}

			case peerStr := <-peerAddrChan:
				if hole.ConnectionPeer.ShouldTryPrivate() {
					hole.ConnectionPeer.Logger.Info.Println("Attempting to connect to private IP address of peer", peerStr, "for peer", hole.ConnectionPeer.PeerID, ". This connection attempt may fail")
				}

				hole.ConnectionPeer.Logger.Debug.Println("Publishing for peer join", hole.ConnectionPeer.PeerID)
				api.GLPPublish(hole.ConnectionPeer.BuildP2PKey(), hole.ConnectionPeer.BuildNetworkEndpointEvent(hole))

				hole.ConnectionPeer.PeerAddr, err = net.ResolveUDPAddr(udp, peerStr)
				if err != nil {
					// pc.Logger.Fatalln("resolve peeraddr:", err)
				}
				conf := ""
				conf += fmt.Sprintf("public_key=%s\n", util.KeyToHex(hole.ConnectionPeer.PeerProfile.PublicKey))
				conf += fmt.Sprintf("endpoint=%s\n", localPeerAddr)
				conf += "replace_allowed_ips=true\n"
				conf += fmt.Sprintf("allowed_ip=%s/32\n", hole.ConnectionPeer.PeerProfile.WireguardIP.String())

				config.SetConfigMulti(hole.ConnectionPeer.Device, conf)

				hole.ConnectionPeer.Started = true
				hole.ConnectionPeer.TriedPrivate = true
				foundPeer <- true
				hole.ConnectionPeer.LastKeepalive = time.Now()

			case <-keepalive:
				err = util.UdpSendStr(keepaliveMsg, hole.ConnectionPeer.LocalPeerConn, hole.ConnectionPeer.PeerAddr)

				if err != nil {
					hole.ConnectionPeer.Logger.Error.Println("keepalive:", err)
				}

				if hole.ConnectionPeer.Started && hole.ConnectionPeer.LastKeepalive.Before(time.Now().Add(-5*time.Second)) {
					hole.ConnectionPeer.Logger.Error.Println("No packet or keepalive received for too long. Connection to", hole.ConnectionPeer.PeerID, "is dead")
					return false
				}
			}
			return true
		}()
		if !res {
			return errors.New("Failed upnpgid")
		}
	}
}

func (hole *UPnPGID) GetPrivateAddr() string {
	return "mysuperipzammit"
}
