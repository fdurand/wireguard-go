package hole

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/fdurand/wireguard-go/ztn/api"
	"github.com/fdurand/wireguard-go/ztn/bufferpool"
	"github.com/fdurand/wireguard-go/ztn/config"
	"github.com/fdurand/wireguard-go/ztn/constants"
	"github.com/fdurand/wireguard-go/ztn/peerconnection"
	"github.com/fdurand/wireguard-go/ztn/util"

	"github.com/inverse-inc/packetfence/go/log"
	"github.com/inverse-inc/packetfence/go/sharedutils"
	"gortc.io/stun"
)

const udp = "udp"
const pingMsg = "ping"

const stunServer = "stun.l.google.com:19302"

type pkt struct {
	raddr   *net.UDPAddr
	message []byte
}

// STUN struct
type STUN struct {
	ExternConn *ExternalConnection
}

//NewSTUN init
func NewSTUN(context context.Context) (Method, error) {
	method := STUN{}
	method.Init(context)
	return &method, nil
}

// Init function
func (hole *STUN) Init(context context.Context) {
	log.SetProcessName("wireguard-go")
	ctx := log.LoggerNewContext(context)
	d := &ExternalConnection{
		extAddr: nil,
		ctx:     ctx,
	}
	hole.ExternConn = d
}

// GetExternalInfo function
func (hole *STUN) GetExternalInfo(context context.Context) (net.UDPAddr, error) {

	var UDP net.UDPAddr
	var err error
	return UDP, err
}

// Run function
func (hole *STUN) Run(pc *peerconnection.PeerConnection) {
	var err error
	pc.WgConn, err = net.DialUDP("udp4", nil, &net.UDPAddr{IP: constants.LocalWGIP, Port: constants.LocalWGPort})
	sharedutils.CheckError(err)

	stunAddr, err := net.ResolveUDPAddr(udp, stunServer)
	sharedutils.CheckError(err)

	pc.LocalPeerConn, err = net.ListenUDP(udp, nil)
	sharedutils.CheckError(err)

	pc.Logger.Debug.Printf("Listening on %s for peer %s\n", pc.LocalPeerConn.LocalAddr(), pc.PeerID)

	var publicAddr stun.XORMappedAddress

	messageChan := make(chan *peerconnection.Pkt)
	pc.Listen(pc.LocalPeerConn, messageChan)
	pc.Listen(pc.WgConn, messageChan)
	var peerAddrChan <-chan string

	keepalive := time.Tick(500 * time.Millisecond)
	keepaliveMsg := pingMsg

	foundPeer := make(chan bool)

	a := strings.Split(pc.LocalPeerConn.LocalAddr().String(), ":")
	var localPeerAddr = fmt.Sprintf("%s:%s", constants.LocalWGIP.String(), a[len(a)-1])
	var localWGAddr = fmt.Sprintf("%s:%d", constants.LocalWGIP.String(), constants.LocalWGPort)

	for {
		res := func() bool {
			var message *peerconnection.Pkt
			var ok bool

			defer func() {
				if message != nil {
					bufferpool.DefaultBufferPool.Put(message.Message)
				}
			}()

			select {
			case message, ok = <-messageChan:
				if !ok {
					return false
				}

				switch {
				case stun.IsMessage(message.Message):
					m := new(stun.Message)
					m.Raw = message.Message
					decErr := m.Decode()
					if decErr != nil {
						pc.Logger.Error.Println("Unable to decode STUN message:", decErr)
						break
					}
					var xorAddr stun.XORMappedAddress
					if getErr := xorAddr.GetFrom(m); getErr != nil {
						pc.Logger.Error.Println("Unable to get STUN XOR address:", getErr)
						break
					}

					if publicAddr.String() != xorAddr.String() {
						pc.Logger.Info.Printf("My public address for peer %s: %s\n", pc.PeerID, xorAddr)
						publicAddr = xorAddr
						pc.MyAddr, err = net.ResolveUDPAddr("udp4", xorAddr.String())
						sharedutils.CheckError(err)

						go func() {
							for {
								select {
								case <-time.After(1 * time.Second):
									pc.Logger.Debug.Println("Publishing IP for discovery with peer", pc.PeerID)
									api.GLPPublish(pc.BuildP2PKey(), pc.BuildNetworkEndpointEvent())
								case <-foundPeer:
									pc.Logger.Info.Println("Found peer", pc.PeerID, ", stopping the publishing")
									return
								}
							}
						}()

						peerAddrChan = pc.GetPeerAddr()
					}

				case string(message.Message) == pingMsg:
					pc.Logger.Debug.Println("Received ping from", pc.PeerAddr)
					pc.LastKeepalive = time.Now()
					pc.Connected = true

				default:
					if message.Raddr.String() == localWGAddr {
						n := len(message.Message)
						pc.Logger.Debug.Printf("send to WG server: [%s]: %d bytes\n", pc.PeerAddr, n)
						util.UdpSend(message.Message, pc.LocalPeerConn, pc.PeerAddr)
					} else {
						n := len(message.Message)
						pc.Logger.Debug.Printf("send to WG server: [%s]: %d bytes\n", pc.WgConn.RemoteAddr(), n)
						pc.WgConn.Write(message.Message)
					}

				}

			case peerStr := <-peerAddrChan:
				if pc.ShouldTryPrivate() {
					pc.Logger.Info.Println("Attempting to connect to private IP address of peer", peerStr, "for peer", pc.PeerID, ". This connection attempt may fail")
				}

				pc.Logger.Debug.Println("Publishing for peer join", pc.PeerID)
				api.GLPPublish(pc.BuildP2PKey(), pc.BuildNetworkEndpointEvent())

				pc.PeerAddr, err = net.ResolveUDPAddr(udp, peerStr)
				if err != nil {
					// pc.Logger.Fatalln("resolve peeraddr:", err)
				}
				conf := ""
				conf += fmt.Sprintf("public_key=%s\n", util.KeyToHex(pc.PeerProfile.PublicKey))
				conf += fmt.Sprintf("endpoint=%s\n", localPeerAddr)
				conf += "replace_allowed_ips=true\n"
				conf += fmt.Sprintf("allowed_ip=%s/32\n", pc.PeerProfile.WireguardIP.String())

				config.SetConfigMulti(pc.Device, conf)

				pc.Started = true
				pc.TriedPrivate = true
				foundPeer <- true
				pc.LastKeepalive = time.Now()

			case <-keepalive:
				// Keep NAT binding alive using STUN server or the peer once it's known
				if pc.PeerAddr == nil {
					err = util.SendBindingRequest(pc.LocalPeerConn, stunAddr)
				} else {
					err = util.UdpSendStr(keepaliveMsg, pc.LocalPeerConn, pc.PeerAddr)
				}

				if err != nil {
					pc.Logger.Error.Println("keepalive:", err)
				}

				if pc.Started && pc.LastKeepalive.Before(time.Now().Add(-5*time.Second)) {
					pc.Logger.Error.Println("No packet or keepalive received for too long. Connection to", pc.PeerID, "is dead")
					return false
				}
			}
			return true
		}()
		if !res {
			return
		}
	}
}
