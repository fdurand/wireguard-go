package hole

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"git.inverse.ca/inverse/fingerbank-processor/sharedutils"
	"github.com/inverse-inc/packetfence/go/log"
	"github.com/inverse-inc/wireguard-go/ztn"
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

//NewSTUN
func NewSTUN(context context.Context) (Method, error) {
	method := STUN{}
	method.Init(context)
	return &method, nil
}

func (hole *STUN) Init(context context.Context) {
	log.SetProcessName("wireguard-go")
	ctx := log.LoggerNewContext(context)
	d := &ExternConnection{
		extAddr: nil,
		ctx:     ctx,
	}
	hole.ExternConn = d
}

func (hole *STUN) GetExternalInfo() (error, net.UDPAddr) {

}

func (hole *STUN) Run(pc *ztn.PeerConnection) {
	var err error
	pc.wgConn, err = net.DialUDP("udp4", nil, &net.UDPAddr{IP: ztn.localWGIP, Port: ztn.localWGPort})
	sharedutils.CheckError(err)

	stunAddr, err := net.ResolveUDPAddr(udp, stunServer)
	sharedutils.CheckError(err)

	pc.localPeerConn, err = net.ListenUDP(udp, nil)
	sharedutils.CheckError(err)

	pc.logger.Debug.Printf("Listening on %s for peer %s\n", pc.localPeerConn.LocalAddr(), pc.peerID)

	var publicAddr stun.XORMappedAddress

	messageChan := make(chan *pkt)
	pc.listen(pc.localPeerConn, messageChan)
	pc.listen(pc.wgConn, messageChan)
	var peerAddrChan <-chan string

	keepalive := time.Tick(500 * time.Millisecond)
	keepaliveMsg := pingMsg

	foundPeer := make(chan bool)

	a := strings.Split(pc.localPeerConn.LocalAddr().String(), ":")
	var localPeerAddr = fmt.Sprintf("%s:%s", ztn.localWGIP.String(), a[len(a)-1])
	var localWGAddr = fmt.Sprintf("%s:%d", ztn.localWGIP.String(), localWGPort)

	for {
		res := func() bool {
			var message *pkt
			var ok bool

			defer func() {
				if message != nil {
					ztn.defaultBufferPool.Put(message.message)
				}
			}()

			select {
			case message, ok = <-messageChan:
				if !ok {
					return false
				}

				switch {
				case stun.IsMessage(message.message):
					m := new(stun.Message)
					m.Raw = message.message
					decErr := m.Decode()
					if decErr != nil {
						pc.logger.Error.Println("Unable to decode STUN message:", decErr)
						break
					}
					var xorAddr stun.XORMappedAddress
					if getErr := xorAddr.GetFrom(m); getErr != nil {
						pc.logger.Error.Println("Unable to get STUN XOR address:", getErr)
						break
					}

					if publicAddr.String() != xorAddr.String() {
						pc.logger.Info.Printf("My public address for peer %s: %s\n", pc.peerID, xorAddr)
						publicAddr = xorAddr
						pc.myAddr, err = net.ResolveUDPAddr("udp4", xorAddr.String())
						sharedutils.CheckError(err)

						go func() {
							for {
								select {
								case <-time.After(1 * time.Second):
									pc.logger.Debug.Println("Publishing IP for discovery with peer", pc.peerID)
									ztn.GLPPublish(pc.buildP2PKey(), pc.buildNetworkEndpointEvent())
								case <-foundPeer:
									pc.logger.Info.Println("Found peer", pc.peerID, ", stopping the publishing")
									return
								}
							}
						}()

						peerAddrChan = pc.getPeerAddr()
					}

				case string(message.message) == pingMsg:
					pc.logger.Debug.Println("Received ping from", pc.peerAddr)
					pc.lastKeepalive = time.Now()
					pc.connected = true

				default:
					if message.raddr.String() == localWGAddr {
						n := len(message.message)
						pc.logger.Debug.Printf("send to WG server: [%s]: %d bytes\n", pc.peerAddr, n)
						ztn.udpSend(message.message, pc.localPeerConn, pc.peerAddr)
					} else {
						n := len(message.message)
						pc.logger.Debug.Printf("send to WG server: [%s]: %d bytes\n", pc.wgConn.RemoteAddr(), n)
						pc.wgConn.Write(message.message)
					}

				}

			case peerStr := <-peerAddrChan:
				if pc.ShouldTryPrivate() {
					pc.logger.Info.Println("Attempting to connect to private IP address of peer", peerStr, "for peer", pc.peerID, ". This connection attempt may fail")
				}

				pc.logger.Debug.Println("Publishing for peer join", pc.peerID)
				ztn.GLPPublish(pc.buildP2PKey(), pc.buildNetworkEndpointEvent())

				pc.peerAddr, err = net.ResolveUDPAddr(udp, peerStr)
				if err != nil {
					log.Fatalln("resolve peeraddr:", err)
				}
				conf := ""
				conf += fmt.Sprintf("public_key=%s\n", ztn.keyToHex(pc.PeerProfile.PublicKey))
				conf += fmt.Sprintf("endpoint=%s\n", localPeerAddr)
				conf += "replace_allowed_ips=true\n"
				conf += fmt.Sprintf("allowed_ip=%s/32\n", pc.PeerProfile.WireguardIP.String())

				ztn.SetConfigMulti(pc.device, conf)

				pc.started = true
				pc.triedPrivate = true
				foundPeer <- true
				pc.lastKeepalive = time.Now()

			case <-keepalive:
				// Keep NAT binding alive using STUN server or the peer once it's known
				if pc.peerAddr == nil {
					err = ztn.sendBindingRequest(pc.localPeerConn, stunAddr)
				} else {
					err = ztn.udpSendStr(keepaliveMsg, pc.localPeerConn, pc.peerAddr)
				}

				if err != nil {
					pc.logger.Error.Println("keepalive:", err)
				}

				if pc.started && pc.lastKeepalive.Before(time.Now().Add(-5*time.Second)) {
					pc.logger.Error.Println("No packet or keepalive received for too long. Connection to", pc.peerID, "is dead")
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
