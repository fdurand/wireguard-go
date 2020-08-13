package peerconnection

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"strings"
	"time"

	"github.com/fdurand/wireguard-go/device"
	"github.com/fdurand/wireguard-go/ztn/api"
	"github.com/fdurand/wireguard-go/ztn/bufferpool"
	"github.com/fdurand/wireguard-go/ztn/profile"
	"github.com/gin-gonic/gin"
	"github.com/inverse-inc/packetfence/go/sharedutils"
)

const udp = "udp"
const pingMsg = "ping"

const stunServer = "stun.l.google.com:19302"

type Pkt struct {
	Raddr   *net.UDPAddr
	Message []byte
}

type PeerConnection struct {
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

func NewPeerConnection(d *device.Device, logger *device.Logger, myProfile profile.Profile, peerProfile profile.PeerProfile) *PeerConnection {
	pc := &PeerConnection{
		Device:      d,
		Logger:      logger,
		myID:        myProfile.PublicKey,
		PeerID:      peerProfile.PublicKey,
		MyProfile:   myProfile,
		PeerProfile: peerProfile,
	}
	return pc
}

func (pc *PeerConnection) Start() {
	for {
		// loop on hole method
		// pc.run()
		pc.reset()
		pc.Logger.Error.Println("Lost connection with", pc.PeerID, ". Reconnecting")
	}
}

func (pc *PeerConnection) reset() {
	pc.WgConn = nil
	pc.LocalPeerConn = nil
	pc.MyAddr = nil
	pc.PeerAddr = nil
	pc.Started = false
	pc.LastKeepalive = time.Time{}

	// Reset the triedPrivate flag if a connection attempt was already successful so that it retries from scratch next time
	if pc.Connected {
		pc.TriedPrivate = false
	}
	pc.Connected = false
}

func (pc *PeerConnection) Listen(conn *net.UDPConn, messages chan *Pkt) {
	go func() {
		for {
			buf := bufferpool.DefaultBufferPool.Get()

			n, raddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				close(messages)
				return
			}
			buf = buf[:n]

			messages <- &Pkt{Raddr: raddr, Message: buf}
		}
	}()
}

func (pc *PeerConnection) BuildP2PKey() string {
	key1 := pc.MyProfile.PublicKey
	key2 := pc.PeerProfile.PublicKey
	if key2 < key1 {
		key1bak := key1
		key1 = key2
		key2 = key1bak
	}

	key1dec, err := base64.StdEncoding.DecodeString(key1)
	sharedutils.CheckError(err)
	key2dec, err := base64.StdEncoding.DecodeString(key2)
	sharedutils.CheckError(err)

	combined := append(key1dec, key2dec...)
	return base64.URLEncoding.EncodeToString(combined)
}

func (pc *PeerConnection) getPrivateAddr() string {
	conn, err := net.Dial("udp", stunServer)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	a := strings.Split(pc.LocalPeerConn.LocalAddr().String(), ":")
	return localAddr.IP.String() + ":" + a[len(a)-1]
}

func (pc *PeerConnection) BuildNetworkEndpointEvent() api.Event {
	return api.Event{Type: "network_endpoint", Data: gin.H{
		"id":               pc.MyProfile.PublicKey,
		"public_endpoint":  pc.MyAddr.String(),
		"private_endpoint": pc.getPrivateAddr(),
	}}
}

func (pc *PeerConnection) GetPeerAddr() <-chan string {
	result := make(chan string)
	myID := pc.MyProfile.PublicKey

	p2pk := pc.BuildP2PKey()

	go func() {
		c := api.GLPClient(p2pk)
		c.Start()
		for {
			select {
			case e := <-c.EventsChan:
				event := api.Event{}
				err := json.Unmarshal(e.Data, &event)
				sharedutils.CheckError(err)
				if event.Type == "network_endpoint" && event.Data["id"].(string) != myID {
					if pc.ShouldTryPrivate() {
						result <- event.Data["private_endpoint"].(string)
						return
					} else {
						result <- event.Data["public_endpoint"].(string)
						return
					}
				}
			}
		}
	}()

	return result
}

func (pc *PeerConnection) ShouldTryPrivate() bool {
	return !pc.TriedPrivate
}
