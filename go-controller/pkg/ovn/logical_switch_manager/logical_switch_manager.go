package logicalswitchmanager

import (
	"fmt"
	"net"

	ipam "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ipallocator"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/subnetipallocator"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

var SwitchNotFound = subnetipallocator.ErrSubnetNotFound

// LogicalSwitchManager provides switch info management APIs including IPAM for the host subnets
type LogicalSwitchManager struct {
	subnetIPAllocator subnetipallocator.SubnetIPAllocator
	reserveIPs        bool
}

// Initializes a new logical switch manager for L3 networks
func NewLogicalSwitchManager() *LogicalSwitchManager {
	return &LogicalSwitchManager{
		subnetIPAllocator: *subnetipallocator.NewSubnetIPAllocator(),
		reserveIPs:        true,
	}
}

func NewL2SwitchManager() *LogicalSwitchManager {
	return &LogicalSwitchManager{
		subnetIPAllocator: *subnetipallocator.NewSubnetIPAllocator(),
	}
}

// AddSwitch adds/updates a switch to the logical switch manager for subnet
// and IPAM management.
func (manager *LogicalSwitchManager) AddSwitch(switchName string, hostSubnets []*net.IPNet) error {
	var reserveIPs []*net.IPNet
	if manager.reserveIPs {
		for _, hostSubnet := range hostSubnets {
			reserveIPs = append(reserveIPs,
				&net.IPNet{IP: util.GetNodeGatewayIfAddr(hostSubnet).IP, Mask: net.CIDRMask(32, 32)},
				&net.IPNet{IP: util.GetNodeManagementIfAddr(hostSubnet).IP, Mask: net.CIDRMask(32, 32)},
			)
		}
	}
	return manager.subnetIPAllocator.AddSubnet(switchName, hostSubnets, reserveIPs...)
}

// AddNoHostSubnetSwitch adds/updates a switch without any host subnets
// to the logical switch manager
func (manager *LogicalSwitchManager) AddNoHostSubnetSwitch(switchName string) error {
	// setting the hostSubnets slice argument to nil in the cache means an object
	// exists for the switch but it was not assigned a hostSubnet by ovn-kubernetes
	// this will be true for switches created on nodes that are marked as host-subnet only.
	return manager.subnetIPAllocator.AddSubnet(switchName, nil)
}

// Remove a switch from the the logical switch manager
func (manager *LogicalSwitchManager) DeleteSwitch(switchName string) {
	manager.subnetIPAllocator.DeleteSubnet(switchName)
}

// Given a switch name, checks if the switch is a noHostSubnet switch
func (manager *LogicalSwitchManager) IsNonHostSubnetSwitch(switchName string) bool {
	subnets, err := manager.subnetIPAllocator.GetSubnets(switchName)
	return err == nil && len(subnets) == 0
}

// Given a switch name, get all its host-subnets
func (manager *LogicalSwitchManager) GetSwitchSubnets(switchName string) []*net.IPNet {
	subnets, _ := manager.subnetIPAllocator.GetSubnets(switchName)
	return subnets
}

// AllocateUntilFull used for unit testing only, allocates the rest of the switch subnet
func (manager *LogicalSwitchManager) AllocateUntilFull(switchName string) error {
	return manager.subnetIPAllocator.AllocateUntilFull(switchName)
}

// AllocateIPs will block off IPs in the ipnets slice as already allocated
// for a given switch
func (manager *LogicalSwitchManager) AllocateIPs(switchName string, ipnets []*net.IPNet) error {
	return manager.subnetIPAllocator.AllocateIPs(switchName, ipnets)
}

// AllocateNextIPs allocates IP addresses from each of the host subnets
// for a given switch
func (manager *LogicalSwitchManager) AllocateNextIPs(switchName string) ([]*net.IPNet, error) {
	return manager.subnetIPAllocator.AllocateNextIPs(switchName)
}

func (manager *LogicalSwitchManager) AllocateHybridOverlay(switchName string, hybridOverlayAnnotation []string) ([]*net.IPNet, error) {
	var err error
	var allocatedAddresses []*net.IPNet

	if len(hybridOverlayAnnotation) > 0 {
		for _, ip := range hybridOverlayAnnotation {
			allocatedAddresses = append(allocatedAddresses, &net.IPNet{IP: net.ParseIP(ip).To4(), Mask: net.CIDRMask(32, 32)})
		}
		// attempt to allocate the IP address that is annotated on the node. The only way there would be a collision is if the annotations of podIP or hybridOverlayDRIP
		// where manually edited and we do not support that
		err = manager.AllocateIPs(switchName, allocatedAddresses)
		if err != nil && err != ipam.ErrAllocated {
			return nil, err
		}
		return allocatedAddresses, nil
	}

	// if we are not provided with any addresses, try to allocate the well known address
	hostSubnets := manager.GetSwitchSubnets(switchName)
	for _, hostSubnet := range hostSubnets {
		allocatedAddresses = append(allocatedAddresses, util.GetNodeHybridOverlayIfAddr(hostSubnet))
	}
	err = manager.AllocateIPs(switchName, allocatedAddresses)
	if err != nil && err != ipam.ErrAllocated {
		return nil, fmt.Errorf("cannot allocate hybrid overlay interface addresses %s for switch %s: %w",
			util.StringIPNets(allocatedAddresses),
			switchName,
			err)
	}

	// otherwise try to allocate any IP
	if err == ipam.ErrAllocated {
		allocatedAddresses, err = manager.AllocateNextIPs(switchName)
	}

	if err != nil {
		return nil, fmt.Errorf("cannot allocate new hybrid overlay interface addresses for switch %s: %w", switchName, err)
	}

	return allocatedAddresses, nil
}

// Mark the IPs in ipnets slice as available for allocation
// by releasing them from the IPAM pool of allocated IPs.
// If there aren't IPs to release the method does not return an error.
func (manager *LogicalSwitchManager) ReleaseIPs(switchName string, ipnets []*net.IPNet) error {
	return manager.subnetIPAllocator.ReleaseIPs(switchName, ipnets)
}

// ConditionalIPRelease determines if any IP is available to be released from an IPAM conditionally if func is true.
// It guarantees state of the allocator will not change while executing the predicate function
// TODO(trozet): add unit testing for this function
func (manager *LogicalSwitchManager) ConditionalIPRelease(switchName string, ipnets []*net.IPNet, predicate func() (bool, error)) (bool, error) {
	return manager.subnetIPAllocator.ConditionalIPRelease(switchName, ipnets, predicate)
}

func (manager *LogicalSwitchManager) WithSwitch(switchName string) *subnetipallocator.IPAllocator {
	return manager.subnetIPAllocator.WithSubnet(switchName)
}
