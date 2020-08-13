// +build !linux android

package device

import (
	"github.com/fdurand/wireguard-go/conn"
	"github.com/fdurand/wireguard-go/rwcancel"
)

func (device *Device) startRouteListener(bind conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
