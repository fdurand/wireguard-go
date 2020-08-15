package profile

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os/exec"

	"github.com/fdurand/wireguard-go/device"
	"github.com/fdurand/wireguard-go/ztn/api"
	"github.com/fdurand/wireguard-go/ztn/config"
	"github.com/fdurand/wireguard-go/ztn/constants"
	"github.com/fdurand/wireguard-go/ztn/util"
	"github.com/inverse-inc/packetfence/go/remoteclients"
	"github.com/inverse-inc/packetfence/go/sharedutils"
)

type ServerChallenge struct {
	Challenge      string `json:"challenge"`
	PublicKey      string `json:"public_key"`
	BytesChallenge []byte
	BytesPublicKey [32]byte
}

func (p *Profile) DoServerChallenge(profile *Profile) string {
	sc, err := p.GetServerChallenge(profile)
	sharedutils.CheckError(err)

	privateKey, err := remoteclients.B64KeyToBytes(profile.PrivateKey)
	sharedutils.CheckError(err)

	publicKey, err := remoteclients.B64KeyToBytes(profile.PublicKey)
	sharedutils.CheckError(err)

	challenge, err := sc.Decrypt(privateKey)
	sharedutils.CheckError(err)

	challenge = append(challenge, publicKey[:]...)

	challengeEncrypted, err := sc.Encrypt(privateKey, challenge)
	sharedutils.CheckError(err)

	return base64.URLEncoding.EncodeToString(challengeEncrypted)
}

func (p *Profile) GetServerChallenge(profile *Profile) (ServerChallenge, error) {
	sc := ServerChallenge{}
	err := api.GetAPIClient().Call(api.APIClientCtx, "GET", "/api/v1/remote_clients/server_challenge?public_key="+url.QueryEscape(util.B64keyToURLb64(profile.PublicKey)), &sc)
	if err != nil {
		return sc, err
	}

	sc.BytesChallenge, err = base64.URLEncoding.DecodeString(sc.Challenge)
	if err != nil {
		return sc, err
	}

	sc.BytesPublicKey, err = remoteclients.URLB64KeyToBytes(sc.PublicKey)
	if err != nil {
		return sc, err
	}

	return sc, nil
}

func (sc *ServerChallenge) Decrypt(privateKey [32]byte) ([]byte, error) {
	sharedSecret := remoteclients.SharedSecret(privateKey, sc.BytesPublicKey)
	return remoteclients.DecryptMessage(sharedSecret[:], sc.BytesChallenge)
}

func (sc *ServerChallenge) Encrypt(privateKey [32]byte, message []byte) ([]byte, error) {
	sharedSecret := remoteclients.SharedSecret(privateKey, sc.BytesPublicKey)
	return remoteclients.EncryptMessage(sharedSecret[:], message)
}

type Profile struct {
	WireguardIP      net.IP   `json:"wireguard_ip"`
	WireguardNetmask int      `json:"wireguard_netmask"`
	PublicKey        string   `json:"public_key"`
	PrivateKey       string   `json:"private_key"`
	AllowedPeers     []string `json:"allowed_peers"`
}

func (p *Profile) SetupWireguard(device *device.Device, WGInterface string) {
	err := exec.Command("ip", "address", "add", "dev", WGInterface, fmt.Sprintf("%s/%d", p.WireguardIP, p.WireguardNetmask)).Run()
	sharedutils.CheckError(err)
	err = exec.Command("ip", "link", "set", WGInterface, "up").Run()
	sharedutils.CheckError(err)

	config.SetConfig(device, "listen_port", fmt.Sprintf("%d", constants.LocalWGPort))
	config.SetConfig(device, "private_key", util.KeyToHex(p.PrivateKey))

}

func (p *Profile) FillProfileFromServer() {
	auth := p.DoServerChallenge(p)

	err := api.GetAPIClient().Call(api.APIClientCtx, "GET", "/api/v1/remote_clients/profile?public_key="+url.QueryEscape(util.B64keyToURLb64(p.PublicKey))+"&auth="+url.QueryEscape(auth), &p)
	sharedutils.CheckError(err)
}

type PeerProfile struct {
	WireguardIP net.IP `json:"wireguard_ip"`
	PublicKey   string `json:"public_key"`
}

func (p *Profile) GetPeerProfile(id string) (PeerProfile, error) {
	var peer PeerProfile
	err := api.GetAPIClient().Call(api.APIClientCtx, "GET", "/api/v1/remote_clients/peer/"+id, &peer)

	pkey, err := base64.URLEncoding.DecodeString(peer.PublicKey)
	sharedutils.CheckError(err)
	p.PublicKey = base64.StdEncoding.EncodeToString(pkey)

	return peer, err
}
