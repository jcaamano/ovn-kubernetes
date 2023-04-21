package config

import (
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"

	utilnet "k8s.io/utils/net"
)

// HostPort is the object that holds the definition for a host and port tuple
type HostPort struct {
	Host *net.IP
	Port int32
}

// String representation of a HostPort entry
func (hp *HostPort) String() string {
	switch {
	case hp.Host == nil:
		return fmt.Sprintf(":%d", hp.Port)
	case hp.Host.To4() != nil:
		return fmt.Sprintf("%s:%d", *hp.Host, hp.Port)
	default:
		return fmt.Sprintf("[%s]:%d", *hp.Host, hp.Port)
	}
}

// CIDRNetworkEntry is the object that holds the definition for a single network CIDR range
type CIDRNetworkEntry struct {
	CIDR             *net.IPNet
	HostSubnetLength int
}

func (c CIDRNetworkEntry) String() string {
	return fmt.Sprintf("%s/%d", c.CIDR.String(), c.HostSubnetLength)
}

// parseClusterSubnetEntriesWithHostSubnets returns the parsed set of
// CIDRNetworkEntries. These entries define a network space by specifying a set
// of CIDR and netmasks the SDN can allocate addresses from including how that
// network space is partitioned. Allows specifying min, max and default host
// subnet lengths for each IP family. Specify a default host subnet length of 0
// if no host subnet length should be allowed when parsing.
func parseClusterSubnetEntriesWithHostSubnets(
	clusterSubnetCmd string,
	defaultIPv4HostSubnetLength, minIPv4HostSubnetLength, maxIPv4HostSubnetLength int,
	defaultIPv6HostSubnetLength, minIPv6HostSubnetLength, maxIPv6HostSubnetLength int) ([]CIDRNetworkEntry, error) {
	var parsedClusterList []CIDRNetworkEntry
	clusterEntriesList := strings.Split(clusterSubnetCmd, ",")

	ipv4HostLengthAllowed := defaultIPv4HostSubnetLength != 0
	ipv6HostLengthAllowed := defaultIPv6HostSubnetLength != 0

	for _, clusterEntry := range clusterEntriesList {
		clusterEntry := strings.TrimSpace(clusterEntry)
		splitClusterEntry := strings.Split(clusterEntry, "/")

		if len(splitClusterEntry) < 2 || len(splitClusterEntry) > 3 {
			return nil, fmt.Errorf("CIDR %q not properly formatted", clusterEntry)
		}

		var err error
		var parsedClusterEntry CIDRNetworkEntry
		_, parsedClusterEntry.CIDR, err = net.ParseCIDR(fmt.Sprintf("%s/%s", splitClusterEntry[0], splitClusterEntry[1]))
		if err != nil {
			return nil, err
		}

		ipv6 := utilnet.IsIPv6(parsedClusterEntry.CIDR.IP)
		hostLengthAllowed := (ipv6 && ipv6HostLengthAllowed) || (!ipv6 && ipv4HostLengthAllowed)

		entryMaskLength, _ := parsedClusterEntry.CIDR.Mask.Size()
		if len(splitClusterEntry) == 3 {
			if !hostLengthAllowed {
				return nil, fmt.Errorf("CIDR %q not properly formatted", clusterEntry)
			}
			tmp, err := strconv.Atoi(splitClusterEntry[2])
			if err != nil {
				return nil, err
			}
			parsedClusterEntry.HostSubnetLength = tmp
		} else {
			if ipv6 {
				parsedClusterEntry.HostSubnetLength = defaultIPv6HostSubnetLength
			} else {
				parsedClusterEntry.HostSubnetLength = defaultIPv4HostSubnetLength
			}
		}

		if !ipv6 && ipv4HostLengthAllowed {
			if parsedClusterEntry.HostSubnetLength < minIPv4HostSubnetLength {
				return nil, fmt.Errorf("IPv6 host subnet /%d smaller than minimum supported /%d",
					parsedClusterEntry.HostSubnetLength,
					minIPv4HostSubnetLength,
				)
			}
			if parsedClusterEntry.HostSubnetLength > maxIPv4HostSubnetLength {
				return nil, fmt.Errorf("IPv6 host subnet /%d bigger than maximum supported /%d",
					parsedClusterEntry.HostSubnetLength,
					maxIPv4HostSubnetLength,
				)
			}
		}

		if ipv6 && ipv6HostLengthAllowed {
			if parsedClusterEntry.HostSubnetLength < 64 {
				return nil, fmt.Errorf("IPv6 host subnet /%d smaller than minimum supported /64",
					parsedClusterEntry.HostSubnetLength)
			}
			if parsedClusterEntry.HostSubnetLength < minIPv6HostSubnetLength {
				return nil, fmt.Errorf("IPv6 host subnet /%d smaller than minimum supported /%d",
					parsedClusterEntry.HostSubnetLength,
					minIPv6HostSubnetLength,
				)
			}
			if parsedClusterEntry.HostSubnetLength > maxIPv6HostSubnetLength {
				return nil, fmt.Errorf("IPv6 host subnet /%d bigger than maximum supported /%d",
					parsedClusterEntry.HostSubnetLength,
					maxIPv6HostSubnetLength,
				)
			}
		}

		if hostLengthAllowed {
			if parsedClusterEntry.HostSubnetLength <= entryMaskLength {
				return nil, fmt.Errorf("cannot use a host subnet length mask shorter than or equal to the cluster subnet mask. "+
					"host subnet length: %d, cluster subnet length: %d", parsedClusterEntry.HostSubnetLength, entryMaskLength)
			}
		}

		parsedClusterList = append(parsedClusterList, parsedClusterEntry)
	}

	if len(parsedClusterList) == 0 {
		return nil, fmt.Errorf("failed to parse any CIDRs from %q", clusterSubnetCmd)
	}

	return parsedClusterList, nil
}

// ParseClusterSubnetEntries returns the parsed set of CIDRNetworkEntries
// including the subnet length to be allocated for each node.
func ParseClusterSubnetEntries(clusterSubnetCmd string) ([]CIDRNetworkEntry, error) {
	// IPv4: for backward compatibility, default to 24 bits host prefix
	// length and don't specifically check maximums and minimums
	// IPv6: only allow 64 bits for host prefix length
	return parseClusterSubnetEntriesWithHostSubnets(clusterSubnetCmd, 24, 0, 32, 64, 64, 64)
}

// ParseClusterSubnetEntriesNoPartitions parses a set of CIDRNetworkEntries
// allowing no host subnet allocation.
func ParseClusterSubnetEntriesNoPartitions(clusterSubnetCmd string) ([]CIDRNetworkEntry, error) {
	return parseClusterSubnetEntriesWithHostSubnets(clusterSubnetCmd, 0, 0, 0, 0, 0, 0)
}

// ParseClusterSubnetEntriesWithDefaultIPv6Partition returns the parsed set of
// CIDRNetworkEntries including the subnet length to be allocated for each node.
// It allows specifying IPv6 partitions bigger than 64 bits.
func ParseClusterSubnetEntriesWithDefaultIPv6Partition(clusterSubnetCmd string, defaultIPv6Partition int) ([]CIDRNetworkEntry, error) {
	return parseClusterSubnetEntriesWithHostSubnets(clusterSubnetCmd, 24, 0, 32, defaultIPv6Partition, 64, 128)
}

// ParseFlowCollectors returns the parsed set of HostPorts passed by the user on the command line
// These entries define the flow collectors OVS will send flow metadata by using NetFlow/SFlow/IPFIX.
func ParseFlowCollectors(flowCollectors string) ([]HostPort, error) {
	var parsedFlowsCollectors []HostPort
	readCollectors := map[string]struct{}{}
	collectors := strings.Split(flowCollectors, ",")
	for _, v := range collectors {
		host, port, err := net.SplitHostPort(v)
		if err != nil {
			return nil, fmt.Errorf("cannot parse hostport: %v", err)
		}
		var ipp *net.IP
		// If the host IP is not provided, we keep it nil and later will assume the Node IP
		if host != "" {
			ip := net.ParseIP(host)
			if ip == nil {
				return nil, fmt.Errorf("collector IP %s is not a valid IP", host)
			}
			ipp = &ip
		}
		parsedPort, err := strconv.ParseInt(port, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("collector port %s is not a valid port: %v", port, err)
		}
		// checking if HostPort entry is duplicate
		hostPort := HostPort{Host: ipp, Port: int32(parsedPort)}
		hps := hostPort.String()
		if _, ok := readCollectors[hps]; ok {
			// duplicate flow collector. Ignore it
			continue
		}
		readCollectors[hps] = struct{}{}
		parsedFlowsCollectors = append(parsedFlowsCollectors, hostPort)
	}

	return parsedFlowsCollectors, nil
}

type configSubnetType string

const (
	configSubnetJoin    configSubnetType = "built-in join subnet"
	configSubnetCluster configSubnetType = "cluster subnet"
	configSubnetService configSubnetType = "service subnet"
	configSubnetHybrid  configSubnetType = "hybrid overlay subnet"
)

type configSubnet struct {
	subnetType configSubnetType
	subnet     *net.IPNet
}

// configSubnets represents a set of configured subnets (and their names)
type configSubnets struct {
	subnets []configSubnet
	v4      map[configSubnetType]bool
	v6      map[configSubnetType]bool
}

// newConfigSubnets returns a new configSubnets
func newConfigSubnets() *configSubnets {
	return &configSubnets{
		v4: make(map[configSubnetType]bool),
		v6: make(map[configSubnetType]bool),
	}
}

// append adds a single subnet to cs
func (cs *configSubnets) append(subnetType configSubnetType, subnet *net.IPNet) {
	cs.subnets = append(cs.subnets, configSubnet{subnetType: subnetType, subnet: subnet})
	if subnetType != configSubnetJoin {
		if utilnet.IsIPv6CIDR(subnet) {
			cs.v6[subnetType] = true
		} else {
			cs.v4[subnetType] = true
		}
	}
}

// checkForOverlaps checks if any of the subnets in cs overlap
func (cs *configSubnets) checkForOverlaps() error {
	for i, si := range cs.subnets {
		for j := 0; j < i; j++ {
			sj := cs.subnets[j]
			if si.subnet.Contains(sj.subnet.IP) || sj.subnet.Contains(si.subnet.IP) {
				return fmt.Errorf("illegal network configuration: %s %q overlaps %s %q",
					si.subnetType, si.subnet.String(),
					sj.subnetType, sj.subnet.String())
			}
		}
	}
	return nil
}

func (cs *configSubnets) describeSubnetType(subnetType configSubnetType) string {
	ipv4 := cs.v4[subnetType]
	ipv6 := cs.v6[subnetType]
	var familyType string
	switch {
	case ipv4 && !ipv6:
		familyType = "IPv4"
	case !ipv4 && ipv6:
		familyType = "IPv6"
	case ipv4 && ipv6:
		familyType = "dual-stack"
	default:
		familyType = "unknown type"
	}
	return familyType + " " + string(subnetType)
}

// checkIPFamilies determines if cs contains a valid single-stack IPv4 configuration, a
// valid single-stack IPv6 configuration, a valid dual-stack configuration, or none of the
// above.
func (cs *configSubnets) checkIPFamilies() (usingIPv4, usingIPv6 bool, err error) {
	if len(cs.v6) == 0 {
		// Single-stack IPv4
		return true, false, nil
	} else if len(cs.v4) == 0 {
		// Single-stack IPv6
		return false, true, nil
	} else if reflect.DeepEqual(cs.v4, cs.v6) {
		// Dual-stack
		return true, true, nil
	}

	netConfig := cs.describeSubnetType(configSubnetCluster)
	netConfig += ", " + cs.describeSubnetType(configSubnetService)
	if cs.v4[configSubnetHybrid] || cs.v6[configSubnetHybrid] {
		netConfig += ", " + cs.describeSubnetType(configSubnetHybrid)
	}

	return false, false, fmt.Errorf("illegal network configuration: %s", netConfig)
}

func ContainsJoinIP(ip net.IP) bool {
	var joinSubnetsConfig []string
	if IPv4Mode {
		joinSubnetsConfig = append(joinSubnetsConfig, Gateway.V4JoinSubnet)
	}
	if IPv6Mode {
		joinSubnetsConfig = append(joinSubnetsConfig, Gateway.V6JoinSubnet)
	}

	for _, subnet := range joinSubnetsConfig {
		_, joinSubnet, _ := net.ParseCIDR(subnet)
		if joinSubnet.Contains(ip) {
			return true
		}
	}
	return false
}
