package main

import (
	"crypto/rand"
	"github.com/vishvananda/netlink"
	"net"
)

func createMACAddress() (net.HardwareAddr, error) {
	hw := make(net.HardwareAddr, 6)
	hw[0] = 0x02 // Locally administered unicast address
	hw[1] = 0x42 // Arbitrary but fixed second byte

	_, err := rand.Read(hw[2:])
	if err != nil {
		return nil, red("failed to generate random bytes for MAC: %w", err)
	}

	return hw, nil
}

func setupVirtualEthOnHost(containerID string) error {
	veth0 := "veth0_" + containerID[:6]
	veth1 := "veth1_" + containerID[:6]
	linkAttrs := netlink.NewLinkAttrs()
	linkAttrs.Name = veth0
	addr, err := createMACAddress()
	if err != nil {
		return err
	}
	veth0Struct := &netlink.Veth{
		LinkAttrs:        linkAttrs,
		PeerName:         veth1,
		PeerHardwareAddr: addr,
	}
	if err := netlink.LinkAdd(veth0Struct); err != nil {
		return err
	}
	netlink.LinkSetUp(veth0Struct)
	gockerBridge, _ := netlink.LinkByName("gocker0")
	netlink.LinkSetMaster(veth0Struct, gockerBridge)

	return nil
}
