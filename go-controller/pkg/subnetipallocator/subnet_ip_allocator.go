package subnetipallocator

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"

	iputils "github.com/containernetworking/plugins/pkg/ip"
	ipam "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ipallocator"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ipallocator/allocator"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"k8s.io/klog/v2"
)

// ErrSubnetNotFound is used to inform the subnet is not being managed
var ErrSubnetNotFound = errors.New("subnet not found")

// subnetInfo contains information corresponding to the subnet. It holds the
// allocations (v4 and v6) as well as the IPAM allocator instances for each
// of the managed subnets
type subnetInfo struct {
	subnets []*net.IPNet
	ipams   []ipam.Interface
}

type ipamFactoryFunc func(*net.IPNet) (ipam.Interface, error)

// SubnetIPAllocator provides IPAM for different subnets
type SubnetIPAllocator struct {
	cache map[string]subnetInfo
	// A RW mutex for LogicalSwitchManager which holds logicalSwitch information
	sync.RWMutex
	ipamFunc ipamFactoryFunc
}

// NewIPAMAllocator provides an ipam interface which can be used for IPAM
// allocations for a given cidr using a contiguous allocation strategy.
// It also pre-allocates certain special subnet IPs such as the .1, .2, and .3
// addresses as reserved.
func NewIPAMAllocator(cidr *net.IPNet) (ipam.Interface, error) {
	return ipam.NewAllocatorCIDRRange(cidr, func(max int, rangeSpec string) (allocator.Interface, error) {
		return allocator.NewRoundRobinAllocationMap(max, rangeSpec), nil
	})
}

// Initializes a new subnet IP allocator
func NewSubnetIPAllocator() *SubnetIPAllocator {
	return &SubnetIPAllocator{
		cache:    make(map[string]subnetInfo),
		RWMutex:  sync.RWMutex{},
		ipamFunc: NewIPAMAllocator,
	}
}

// AddSubnet to the allocator for IPAM management
func (allocator *SubnetIPAllocator) AddSubnet(subnetName string, subnets []*net.IPNet, excludes ...*net.IPNet) error {
	allocator.Lock()
	defer allocator.Unlock()
	if subnetInfo, ok := allocator.cache[subnetName]; ok && !reflect.DeepEqual(subnetInfo.subnets, subnets) {
		klog.Warningf("Replacing subnets %v with %v for %s", util.StringIPNets(subnetInfo.subnets), util.StringIPNets(subnets), subnetName)
	}
	var ipams []ipam.Interface
	for _, subnet := range subnets {
		ipam, err := allocator.ipamFunc(subnet)
		if err != nil {
			return fmt.Errorf("failed to initialize IPAM of subnet %s for %s: %w", subnet, subnetName, err)
		}
		ipams = append(ipams, ipam)
	}
	allocator.cache[subnetName] = subnetInfo{
		subnets: subnets,
		ipams:   ipams,
	}

	for _, exclude := range excludes {
		var excluded bool
		for i, subnet := range subnets {
			if util.ContainsCIDR(subnet, exclude) {
				err := reserveIPs(exclude, ipams[i])
				if err != nil {
					return fmt.Errorf("failed to exclude subnet %s for %s: %w", exclude, subnetName, err)
				}
			}
			excluded = true
		}
		if !excluded {
			return fmt.Errorf("failed to exclude subnet %s for %s: not contained in any of the subnets", exclude, subnetName)
		}
	}

	return nil
}

// DeleteSubnet from the allocator
func (allocator *SubnetIPAllocator) DeleteSubnet(subnetName string) {
	allocator.Lock()
	defer allocator.Unlock()
	delete(allocator.cache, subnetName)
}

// GetSubnets for a given subnet name
func (allocator *SubnetIPAllocator) GetSubnets(subnetName string) ([]*net.IPNet, error) {
	allocator.RLock()
	defer allocator.RUnlock()
	subnetInfo, ok := allocator.cache[subnetName]
	// make a deep-copy of the underlying slice and return so that there is no
	// resource contention
	if ok {
		subnets := make([]*net.IPNet, len(subnetInfo.subnets))
		for i, subnet := range subnetInfo.subnets {
			subnet := *subnet
			subnets[i] = &subnet
		}
		return subnets, nil
	}
	return nil, ErrSubnetNotFound
}

// AllocateUntilFull used for unit testing only, allocates the rest of the subnet
func (allocator *SubnetIPAllocator) AllocateUntilFull(subnetName string) error {
	allocator.RLock()
	defer allocator.RUnlock()
	subnetInfo, ok := allocator.cache[subnetName]
	if !ok {
		return fmt.Errorf("failed to allocate IPs for subnet %s: %w", subnetName, ErrSubnetNotFound)
	} else if len(subnetInfo.ipams) == 0 {
		return fmt.Errorf("failed to allocate IPs for subnet %s: has no IPAM", subnetName)
	}
	var err error
	for err != ipam.ErrFull {
		for _, ipam := range subnetInfo.ipams {
			_, err = ipam.AllocateNext()
		}
	}
	return nil
}

// AllocateIPs will block off IPs in the ipnets slice as already allocated
// for a given subnet
func (allocator *SubnetIPAllocator) AllocateIPs(subnetName string, ipnets []*net.IPNet) error {
	if len(ipnets) == 0 {
		return fmt.Errorf("failed to allocate IPs for %s: no IPs provided", subnetName)
	}
	allocator.RLock()
	defer allocator.RUnlock()
	subnetInfo, ok := allocator.cache[subnetName]
	if !ok {
		return fmt.Errorf("failed to allocate IPs %v for %s: %w", util.StringIPNets(ipnets), subnetName, ErrSubnetNotFound)
	} else if len(subnetInfo.ipams) == 0 {
		return fmt.Errorf("failed to allocate IPs %v for subnet %s: has no IPAM", util.StringIPNets(ipnets), subnetName)
	}

	var err error
	allocated := make(map[int]*net.IPNet)
	defer func() {
		if err != nil {
			// iterate over range of already allocated indices and release
			// ips allocated before the error occurred.
			for relIdx, relIPNet := range allocated {
				subnetInfo.ipams[relIdx].Release(relIPNet.IP)
				if relIPNet.IP != nil {
					klog.Warningf("Reserved IP %s was released for %s", relIPNet.IP, subnetName)
				}
			}
		}
	}()

	for _, ipnet := range ipnets {
		for idx, ipam := range subnetInfo.ipams {
			cidr := ipam.CIDR()
			if cidr.Contains(ipnet.IP) {
				if _, ok = allocated[idx]; ok {
					err = fmt.Errorf("failed to allocate IP %s for %s: attempted to reserve multiple IPs in the same IPAM instance", ipnet.IP, subnetName)
					return err
				}
				if err = ipam.Allocate(ipnet.IP); err != nil {
					return err
				}
				allocated[idx] = ipnet
				break
			}
		}
	}
	return nil
}

// reserveIPs reserves subnet IPs
func reserveIPs(subnet *net.IPNet, ipam ipam.Interface) error {
	// FIXME: allocate IP ranges when https://github.com/ovn-org/ovn-kubernetes/issues/3369 is fixed
	for ip := subnet.IP; subnet.Contains(ip); ip = iputils.NextIP(ip) {
		if ipam.Reserved(ip) {
			continue
		}
		err := ipam.Allocate(ip)
		if err != nil {
			return fmt.Errorf("failed to reserve IP %s: %w", ip, err)
		}
	}
	return nil
}

// AllocateNextIPs allocates IP addresses from each of the subnets
func (allocator *SubnetIPAllocator) AllocateNextIPs(subnetName string) ([]*net.IPNet, error) {
	allocator.RLock()
	defer allocator.RUnlock()
	var ipnets []*net.IPNet
	var ip net.IP
	var err error
	subnetInfo, ok := allocator.cache[subnetName]

	if !ok {
		return nil, fmt.Errorf("failed to allocate new IPs for %s: %w", subnetName, ErrSubnetNotFound)
	}

	if len(subnetInfo.ipams) == 0 {
		return nil, fmt.Errorf("failed to allocate new IPs for %s: has no IPAM", subnetName)
	}

	if len(subnetInfo.ipams) != len(subnetInfo.subnets) {
		return nil, fmt.Errorf("failed to allocate new IPs for %s: number of subnets %d"+
			" don't match number of ipam instances %d", subnetName, len(subnetInfo.subnets), len(subnetInfo.ipams))
	}

	defer func() {
		if err != nil {
			// iterate over range of already allocated indices and release
			// ips allocated before the error occurred.
			for relIdx, relIPNet := range ipnets {
				subnetInfo.ipams[relIdx].Release(relIPNet.IP)
				if relIPNet.IP != nil {
					klog.Warningf("Reserved IP %s was released for %s", relIPNet.IP, subnetName)
				}
			}
		}
	}()

	for idx, ipam := range subnetInfo.ipams {
		ip, err = ipam.AllocateNext()
		if err != nil {
			return nil, err
		}
		ipnet := &net.IPNet{
			IP:   ip,
			Mask: subnetInfo.subnets[idx].Mask,
		}
		ipnets = append(ipnets, ipnet)
	}
	return ipnets, nil
}

// ReleaseIPs marks the IPs in ipnets slice as available for allocation
// by releasing them from the IPAM pool of allocated IPs.
// If there aren't IPs to release the method does not return an error.
func (allocator *SubnetIPAllocator) ReleaseIPs(subnetName string, ipnets []*net.IPNet) error {
	allocator.RLock()
	defer allocator.RUnlock()
	if ipnets == nil || subnetName == "" {
		return nil
	}
	subnetInfo, ok := allocator.cache[subnetName]
	if !ok {
		return fmt.Errorf("failed to release ips for %s: %w", subnetName, ErrSubnetNotFound)
	}

	for _, ipnet := range ipnets {
		for _, ipam := range subnetInfo.ipams {
			cidr := ipam.CIDR()
			if cidr.Contains(ipnet.IP) {
				ipam.Release(ipnet.IP)
				break
			}
		}
	}
	return nil
}

// ConditionalIPRelease determines if any IP is available to be released from an IPAM conditionally if func is true.
// It guarantees state of the allocator will not change while executing the predicate function
// TODO(trozet): add unit testing for this function
func (allocator *SubnetIPAllocator) ConditionalIPRelease(subnetName string, ipnets []*net.IPNet, predicate func() (bool, error)) (bool, error) {
	allocator.RLock()
	defer allocator.RUnlock()
	if ipnets == nil || subnetName == "" {
		return false, nil
	}
	subnetInfo, ok := allocator.cache[subnetName]
	if !ok {
		return false, nil
	}
	if len(subnetInfo.ipams) == 0 {
		return false, nil
	}

	// check if ipam has one of the ip addresses, and then execute the predicate function to determine
	// if this IP should be released or not
	for _, ipnet := range ipnets {
		for _, ipam := range subnetInfo.ipams {
			cidr := ipam.CIDR()
			if cidr.Contains(ipnet.IP) {
				if ipam.Has(ipnet.IP) {
					return predicate()
				}
			}
		}
	}

	return false, nil
}

func (allocator *SubnetIPAllocator) WithSubnet(subnetName string) *IPAllocator {
	return &IPAllocator{
		subnetName: subnetName,
		allocator:  allocator,
	}
}

type IPAllocator struct {
	allocator  *SubnetIPAllocator
	subnetName string
}

func (ipAllocator *IPAllocator) GetSubnets() ([]*net.IPNet, error) {
	return ipAllocator.allocator.GetSubnets(ipAllocator.subnetName)
}

func (ipAllocator *IPAllocator) AllocateIPs(ips []*net.IPNet) error {
	return ipAllocator.allocator.AllocateIPs(ipAllocator.subnetName, ips)
}

func (ipAllocator *IPAllocator) AllocateNextIPs() ([]*net.IPNet, error) {
	return ipAllocator.allocator.AllocateNextIPs(ipAllocator.subnetName)
}

func (ipAllocator *IPAllocator) ReleaseIPs(ips []*net.IPNet) error {
	return ipAllocator.allocator.ReleaseIPs(ipAllocator.subnetName, ips)
}
