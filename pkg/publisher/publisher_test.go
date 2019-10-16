package publisher

import (
	"fmt"
	"net"
	"testing"

	"github.com/sirupsen/logrus"
)

const (
	flagUp       = net.FlagUp | net.FlagBroadcast | net.FlagMulticast
	flagDown     = net.FlagBroadcast | net.FlagMulticast
	flagLoopback = net.FlagUp | net.FlagLoopback
	flagP2P      = net.FlagUp | net.FlagPointToPoint
)

func makeIntf(index int, name string, flags net.Flags) net.Interface {
	mac := net.HardwareAddr{0, 0x32, 0x7d, 0x69, 0xf7, byte(0x30 + index)}
	return net.Interface{
		Index:        index,
		MTU:          1500,
		Name:         name,
		HardwareAddr: mac,
		Flags:        flags}
}

var (
	downIntf     = makeIntf(1, "eth3", flagDown)
	loopbackIntf = makeIntf(1, "lo", flagLoopback)
	p2pIntf      = makeIntf(1, "lo", flagP2P)
	upIntf       = makeIntf(1, "eth3", flagUp)
)

func TestPublish(t *testing.T) {
}

func TestFindIFace(t *testing.T) {
	SetLogLevel(logrus.DebugLevel)
	testCases := []struct {
		tcase      string
		nwname     string
		ip         net.IP
		nw         networkInterfacer
		expected   string
		errStrFrag string
	}{
		{"ipv4", "eth3", net.ParseIP("10.254.71.145"), validNetworkInterface{}, "eth3", ""},
		{"ipv6", "eth3", net.ParseIP("2001::200"), ipv6NetworkInterface{}, "eth3", ""},
		{"ipv4 multi", "eth3", net.ParseIP("192.168.111.100"), validNetworkInterfaceMulti{}, "eth3", ""},
		{"no ipv4", "eth3", net.ParseIP("192.168.111.100"), ipv6NetworkInterface{}, "", ""},
		{"ipv6 no ipv4", "eth3", net.ParseIP("2001::200"), ipv6NetworkInterface{}, "eth3", ""},
		{"noiface", "eth3", net.ParseIP("192.168.111.100"), noNetworkInterface{}, "", ""},
		{"fail get addr", "eth3", net.ParseIP("192.168.111.100"), networkInterfaceFailGetAddrs{}, "", "unable to get Addrs"},
		{"bad addr", "eth3", net.ParseIP("192.168.111.100"), networkInterfaceWithInvalidAddr{}, "", "invalid CIDR"},
	}
	for _, tc := range testCases {
		iface, err := findIface(tc.ip, tc.nw)
		if !(iface.Name == tc.expected) {
			t.Errorf("case[%v]: expected %v, got %+v .err : %v", tc.tcase, tc.expected, iface.Name, err)
		}
	}
}

func TestIfaceCheck(t *testing.T) {

}

type addrStruct struct{ val string }

func (a addrStruct) Network() string {
	return a.val
}
func (a addrStruct) String() string {
	return a.val
}

// Has a valid IPv4 address (IPv6 is LLA)
type validNetworkInterface struct {
}

func (_ validNetworkInterface) InterfaceByName(intfName string) (*net.Interface, error) {
	return &upIntf, nil
}
func (_ validNetworkInterface) Addrs(intf *net.Interface) ([]net.Addr, error) {
	var ifat []net.Addr
	ifat = []net.Addr{
		addrStruct{val: "fe80::2f7:6fff:fe6e:2956"}, addrStruct{val: "10.254.71.145"}}
	return ifat, nil
}
func (_ validNetworkInterface) Interfaces() ([]net.Interface, error) {
	return []net.Interface{upIntf}, nil
}

// Has multiple valid IPv4 addresses (IPv6 is LLA)
type validNetworkInterfaceMulti struct {
}

func (_ validNetworkInterfaceMulti) InterfaceByName(intfName string) (*net.Interface, error) {
	return &upIntf, nil
}
func (_ validNetworkInterfaceMulti) Addrs(intf *net.Interface) ([]net.Addr, error) {
	var ifat []net.Addr
	ifat = []net.Addr{
		addrStruct{val: "fe80::2f7:6fff:fe6e:2956"}, addrStruct{val: "10.254.71.145"}, addrStruct{val: "192.168.111.100"}}
	return ifat, nil
}
func (_ validNetworkInterfaceMulti) Interfaces() ([]net.Interface, error) {
	return []net.Interface{upIntf}, nil
}

// Interface with only IPv6 address
type ipv6NetworkInterface struct {
}

func (_ ipv6NetworkInterface) InterfaceByName(intfName string) (*net.Interface, error) {
	return &upIntf, nil
}
func (_ ipv6NetworkInterface) Addrs(intf *net.Interface) ([]net.Addr, error) {
	var ifat []net.Addr
	ifat = []net.Addr{addrStruct{val: "2001::200"}}
	return ifat, nil
}

func (_ ipv6NetworkInterface) Interfaces() ([]net.Interface, error) {
	return []net.Interface{upIntf}, nil
}

// No interfaces
type noNetworkInterface struct {
}

func (_ noNetworkInterface) InterfaceByName(intfName string) (*net.Interface, error) {
	return nil, fmt.Errorf("no such network interface")
}
func (_ noNetworkInterface) Addrs(intf *net.Interface) ([]net.Addr, error) {
	return nil, nil
}
func (_ noNetworkInterface) Interfaces() ([]net.Interface, error) {
	return []net.Interface{}, nil
}

// Unable to get IP addresses for interface
type networkInterfaceFailGetAddrs struct {
}

func (_ networkInterfaceFailGetAddrs) InterfaceByName(intfName string) (*net.Interface, error) {
	return &upIntf, nil
}
func (_ networkInterfaceFailGetAddrs) Addrs(intf *net.Interface) ([]net.Addr, error) {
	return nil, fmt.Errorf("unable to get Addrs")
}
func (_ networkInterfaceFailGetAddrs) Interfaces() ([]net.Interface, error) {
	return []net.Interface{upIntf}, nil
}

// No addresses for interface
type networkInterfaceWithNoAddrs struct {
}

func (_ networkInterfaceWithNoAddrs) InterfaceByName(intfName string) (*net.Interface, error) {
	return &upIntf, nil
}
func (_ networkInterfaceWithNoAddrs) Addrs(intf *net.Interface) ([]net.Addr, error) {
	ifat := []net.Addr{}
	return ifat, nil
}
func (_ networkInterfaceWithNoAddrs) Interfaces() ([]net.Interface, error) {
	return []net.Interface{upIntf}, nil
}

// Invalid addresses for interface
type networkInterfaceWithInvalidAddr struct {
}

func (_ networkInterfaceWithInvalidAddr) InterfaceByName(intfName string) (*net.Interface, error) {
	return &upIntf, nil
}
func (_ networkInterfaceWithInvalidAddr) Addrs(intf *net.Interface) ([]net.Addr, error) {
	var ifat []net.Addr
	ifat = []net.Addr{addrStruct{val: "10.20.30.40.50/24"}}
	return ifat, nil
}
func (_ networkInterfaceWithInvalidAddr) Interfaces() ([]net.Interface, error) {
	return []net.Interface{upIntf}, nil
}
