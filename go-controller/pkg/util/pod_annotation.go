package util

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	nadapi "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	nadutils "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"

	v1 "k8s.io/api/core/v1"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

// This handles the "k8s.ovn.org/pod-networks" annotation on Pods, used to pass
// information about networking from the master to the nodes. (The util.PodAnnotation
// struct is also embedded in the cni.PodInterfaceInfo type that is passed from the
// cniserver to the CNI shim.)
//
// The annotation looks like:
//
//   annotations:
//     k8s.ovn.org/pod-networks: |
//       {
//         "default": {
//           "ip_addresses": ["192.168.0.5/24"],
//           "mac_address": "0a:58:fd:98:00:01",
//           "gateway_ips": ["192.168.0.1"]
//
//           # for backward compatibility
//           "ip_address": "192.168.0.5/24",
//           "gateway_ip": "192.168.0.1"
//         }
//       }
//
// (With optional additional "routes" also indicated; in particular, if a pod has an
// additional network attachment that claims the default route, then the "default" network
// will have explicit routes to the cluster and service subnets.)
//
// The "ip_address" and "gateway_ip" fields are deprecated and will eventually go away.
// (And they are not output when "ip_addresses" or "gateway_ips" contains multiple
// values.)

const (
	// OvnPodAnnotationName is the constant string representing the POD annotation key
	OvnPodAnnotationName = "k8s.ovn.org/pod-networks"
	// DefNetworkAnnotation is the pod annotation for the cluster-wide default network
	DefNetworkAnnotation = "v1.multus-cni.io/default-network"
)

var ErrNoPodIPFound = errors.New("no pod IPs found")
var ErrOverridePodIPs = errors.New("requested pod IPs trying to override IPs exists in pod annotation")

// PodAnnotation describes the assigned network details for a single pod network. (The
// actual annotation may include the equivalent of multiple PodAnnotations.)
type PodAnnotation struct {
	// IPs are the pod's assigned IP addresses/prefixes
	IPs []*net.IPNet
	// MAC is the pod's assigned MAC address
	MAC net.HardwareAddr
	// Gateways are the pod's gateway IP addresses; note that there may be
	// fewer Gateways than IPs.
	Gateways []net.IP
	// Routes are additional routes to add to the pod's network namespace
	Routes []PodRoute
}

// PodRoute describes any routes to be added to the pod's network namespace
type PodRoute struct {
	// Dest is the route destination
	Dest *net.IPNet
	// NextHop is the IP address of the next hop for traffic destined for Dest
	NextHop net.IP
}

// Internal struct used to marshal PodAnnotation to the pod annotation
type podAnnotation struct {
	IPs      []string   `json:"ip_addresses"`
	MAC      string     `json:"mac_address"`
	Gateways []string   `json:"gateway_ips,omitempty"`
	Routes   []podRoute `json:"routes,omitempty"`

	IP      string `json:"ip_address,omitempty"`
	Gateway string `json:"gateway_ip,omitempty"`
}

// Internal struct used to marshal PodRoute to the pod annotation
type podRoute struct {
	Dest    string `json:"dest"`
	NextHop string `json:"nextHop"`
}

// MarshalPodAnnotation adds the pod's network details of the specified network to the corresponding pod annotation.
func MarshalPodAnnotation(annotations map[string]string, podInfo *PodAnnotation, nadName string) (map[string]string, error) {
	if annotations == nil {
		annotations = make(map[string]string)
	}
	podNetworks, err := UnmarshalPodAnnotationAllNetworks(annotations)
	if err != nil {
		return nil, err
	}
	pa := podAnnotation{
		MAC: podInfo.MAC.String(),
	}

	if len(podInfo.IPs) == 1 {
		pa.IP = podInfo.IPs[0].String()
		if len(podInfo.Gateways) == 1 {
			pa.Gateway = podInfo.Gateways[0].String()
		} else if len(podInfo.Gateways) > 1 {
			return nil, fmt.Errorf("bad podNetwork data: single-stack network can only have a single gateway")
		}
	}
	for _, ip := range podInfo.IPs {
		pa.IPs = append(pa.IPs, ip.String())
	}

	existingPa, ok := podNetworks[nadName]
	if ok {
		if len(pa.IPs) != len(existingPa.IPs) {
			return nil, ErrOverridePodIPs
		}
		for _, ip := range pa.IPs {
			if !SliceHasStringItem(existingPa.IPs, ip) {
				return nil, ErrOverridePodIPs
			}
		}
	}

	for _, gw := range podInfo.Gateways {
		pa.Gateways = append(pa.Gateways, gw.String())
	}

	for _, r := range podInfo.Routes {
		if r.Dest.IP.IsUnspecified() {
			return nil, fmt.Errorf("bad podNetwork data: default route %v should be specified as gateway", r)
		}
		var nh string
		if r.NextHop != nil {
			nh = r.NextHop.String()
		}
		pa.Routes = append(pa.Routes, podRoute{
			Dest:    r.Dest.String(),
			NextHop: nh,
		})
	}
	podNetworks[nadName] = pa
	bytes, err := json.Marshal(podNetworks)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling podNetworks map %v", podNetworks)
	}
	annotations[OvnPodAnnotationName] = string(bytes)
	return annotations, nil
}

// UnmarshalPodAnnotation returns the Pod's network info of the given network from pod.Annotations
func UnmarshalPodAnnotation(annotations map[string]string, nadName string) (*PodAnnotation, error) {
	var err error
	ovnAnnotation, ok := annotations[OvnPodAnnotationName]
	if !ok {
		return nil, newAnnotationNotSetError("could not find OVN pod annotation in %v", annotations)
	}

	podNetworks, err := UnmarshalPodAnnotationAllNetworks(annotations)
	if err != nil {
		return nil, err
	}

	tempA, ok := podNetworks[nadName]
	if !ok {
		return nil, fmt.Errorf("no ovn pod annotation for network %s: %q",
			nadName, ovnAnnotation)
	}

	a := &tempA

	podAnnotation := &PodAnnotation{}
	if a.MAC != "" {
		podAnnotation.MAC, err = net.ParseMAC(a.MAC)
		if err != nil {
			return nil, fmt.Errorf("failed to parse pod MAC %q: %v", a.MAC, err)
		}
	}

	if len(a.IPs) == 0 {
		if a.IP != "" {
			a.IPs = append(a.IPs, a.IP)
		}
	} else if a.IP != "" && a.IP != a.IPs[0] {
		return nil, fmt.Errorf("bad annotation data (ip_address and ip_addresses conflict)")
	}
	for _, ipstr := range a.IPs {
		ip, ipnet, err := net.ParseCIDR(ipstr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse pod IP %q: %v", ipstr, err)
		}
		ipnet.IP = ip
		podAnnotation.IPs = append(podAnnotation.IPs, ipnet)
	}

	if len(a.Gateways) == 0 {
		if a.Gateway != "" {
			a.Gateways = append(a.Gateways, a.Gateway)
		}
	} else if a.Gateway != "" && a.Gateway != a.Gateways[0] {
		return nil, fmt.Errorf("bad annotation data (gateway_ip and gateway_ips conflict)")
	}
	for _, gwstr := range a.Gateways {
		gw := net.ParseIP(gwstr)
		if gw == nil {
			return nil, fmt.Errorf("failed to parse pod gateway %q", gwstr)
		}
		podAnnotation.Gateways = append(podAnnotation.Gateways, gw)
	}

	for _, r := range a.Routes {
		route := PodRoute{}
		_, route.Dest, err = net.ParseCIDR(r.Dest)
		if err != nil {
			return nil, fmt.Errorf("failed to parse pod route dest %q: %v", r.Dest, err)
		}
		if route.Dest.IP.IsUnspecified() {
			return nil, fmt.Errorf("bad podNetwork data: default route %v should be specified as gateway", route)
		}
		if r.NextHop != "" {
			route.NextHop = net.ParseIP(r.NextHop)
			if route.NextHop == nil {
				return nil, fmt.Errorf("failed to parse pod route next hop %q", r.NextHop)
			} else if utilnet.IsIPv6(route.NextHop) != utilnet.IsIPv6CIDR(route.Dest) {
				return nil, fmt.Errorf("pod route %s has next hop %s of different family", r.Dest, r.NextHop)
			}
		}
		podAnnotation.Routes = append(podAnnotation.Routes, route)
	}

	return podAnnotation, nil
}

func UnmarshalPodAnnotationAllNetworks(annotations map[string]string) (map[string]podAnnotation, error) {
	podNetworks := make(map[string]podAnnotation)
	ovnAnnotation, ok := annotations[OvnPodAnnotationName]
	if ok {
		if err := json.Unmarshal([]byte(ovnAnnotation), &podNetworks); err != nil {
			return nil, fmt.Errorf("failed to unmarshal ovn pod annotation %q: %v",
				ovnAnnotation, err)
		}
	}
	return podNetworks, nil
}

// GetPodCIDRsWithFullMask returns the pod's IP addresses in a CIDR with FullMask format
// Internally it calls GetPodIPsOfNetwork
func GetPodCIDRsWithFullMask(pod *v1.Pod, nInfo NetInfo) ([]*net.IPNet, error) {
	podIPs, err := GetPodIPsOfNetwork(pod, nInfo)
	if err != nil {
		return nil, err
	}
	ips := make([]*net.IPNet, 0, len(podIPs))
	for _, podIP := range podIPs {
		podIPStr := podIP.String()
		mask := GetIPFullMask(podIPStr)
		_, ipnet, err := net.ParseCIDR(podIPStr + mask)
		if err != nil {
			// this should not happen;
			klog.Warningf("Failed to parse pod IP %v err: %v", podIP, err)
			continue
		}
		ips = append(ips, ipnet)
	}
	return ips, nil
}

// GetPodIPsOfNetwork returns the pod's IP addresses, first from the OVN annotation
// and then falling back to the Pod Status IPs. This function is intended to
// also return IPs for HostNetwork and other non-OVN-IPAM-ed pods.
func GetPodIPsOfNetwork(pod *v1.Pod, nInfo NetInfo) ([]net.IP, error) {
	ips := []net.IP{}
	networkMap := map[string]*nadapi.NetworkSelectionElement{}
	if !nInfo.IsSecondary() {
		// default network, Pod annotation is under the name of DefaultNetworkName
		networkMap[types.DefaultNetworkName] = nil
	} else {
		var err error
		var on bool

		on, networkMap, err = GetPodNADToNetworkMapping(pod, nInfo)
		if err != nil {
			return nil, err
		} else if !on {
			// the pod is not attached to this specific network, don't return error
			return []net.IP{}, nil
		}
	}
	for nadName := range networkMap {
		annotation, _ := UnmarshalPodAnnotation(pod.Annotations, nadName)
		if annotation != nil {
			// Use the OVN annotation if valid
			for _, ip := range annotation.IPs {
				ips = append(ips, ip.IP)
			}
			// An OVN annotation should never have empty IPs, but just in case
			if len(ips) == 0 {
				klog.Warningf("No IPs found in existing OVN annotation for NAD %s! Pod Name: %s, Annotation: %#v",
					nadName, pod.Name, annotation)
			}
		}
	}
	if len(ips) != 0 {
		return ips, nil
	}

	if nInfo.IsSecondary() {
		return []net.IP{}, fmt.Errorf("no pod annotation of pod %s/%s found for network %s",
			pod.Namespace, pod.Name, nInfo.GetNetworkName())
	}

	// Otherwise, default network, if the annotation is not valid try to use Kube API pod IPs
	ips = make([]net.IP, 0, len(pod.Status.PodIPs))
	for _, podIP := range pod.Status.PodIPs {
		ip := utilnet.ParseIPSloppy(podIP.IP)
		if ip == nil {
			klog.Warningf("Failed to parse pod IP %q", podIP)
			continue
		}
		ips = append(ips, ip)
	}

	if len(ips) > 0 {
		return ips, nil
	}

	// Fallback check pod.Status.PodIP
	// Kubelet < 1.16 only set podIP
	ip := utilnet.ParseIPSloppy(pod.Status.PodIP)
	if ip == nil {
		return nil, fmt.Errorf("pod %s/%s: %w ", pod.Namespace, pod.Name, ErrNoPodIPFound)
	}

	return []net.IP{ip}, nil
}

// GetK8sPodDefaultNetworkSelection get pod default network from annotations
func GetK8sPodDefaultNetworkSelection(pod *v1.Pod) (*nadapi.NetworkSelectionElement, error) {
	var netAnnot string

	netAnnot, ok := pod.Annotations[DefNetworkAnnotation]
	if !ok {
		return nil, nil
	}

	networks, err := nadutils.ParseNetworkAnnotation(netAnnot, pod.Namespace)
	if err != nil {
		return nil, fmt.Errorf("GetK8sPodDefaultNetwork: failed to parse CRD object: %v", err)
	}
	if len(networks) > 1 {
		return nil, fmt.Errorf("GetK8sPodDefaultNetwork: more than one default network is specified: %s", netAnnot)
	}

	if len(networks) == 1 {
		return networks[0], nil
	}

	return nil, nil
}

// GetK8sPodAllNetworkSelections get pod's all network NetworkSelectionElement from k8s.v1.cni.cncf.io/networks annotation
func GetK8sPodAllNetworkSelections(pod *v1.Pod) ([]*nadapi.NetworkSelectionElement, error) {
	networks, err := nadutils.ParsePodNetworkAnnotation(pod)
	if err != nil {
		if _, ok := err.(*nadapi.NoK8sNetworkError); !ok {
			return nil, fmt.Errorf("failed to get all NetworkSelectionElements for pod %s/%s: %v", pod.Namespace, pod.Name, err)
		}
		networks = []*nadapi.NetworkSelectionElement{}
	}
	return networks, nil
}

type ipAllocator interface {
	GetSubnets() ([]*net.IPNet, error)
	AllocateIPs(ips []*net.IPNet) error
	AllocateNextIPs() ([]*net.IPNet, error)
	ReleaseIPs(ips []*net.IPNet) error
}

type errAllocated struct{}

func (e errAllocated) Is(target error) bool {
	return target.Error() == "provided IP is already allocated"
}

func (e errAllocated) Error() string {
	return "provided IP is already allocated"
}

type podAnnotationUpdate func(p *v1.Pod, a *PodAnnotation, nad string) error

type PodAnnotationAllocator struct {
	NetInfo             NetInfo
	IPAllocator         ipAllocator
	PodAnnotationUpdate podAnnotationUpdate
}

func (pa PodAnnotationAllocator) AllocatePodAnnotation(pod *v1.Pod, podAnnotation *PodAnnotation, network *nadapi.NetworkSelectionElement, reallocateOnError bool) (
	*PodAnnotation, bool, error) {
	var err error
	var releaseIPs, needsAnnotationUpdate bool
	nadName := types.DefaultNetworkName
	if pa.NetInfo.IsSecondary() {
		nadName = GetNADName(network.Namespace, network.Name)
	}
	podDesc := fmt.Sprintf("%s/%s/%s", nadName, pod.Namespace, pod.Name)

	if podAnnotation == nil {
		podAnnotation = &PodAnnotation{}
	}

	// the IPs we allocate in this function need to be released back to the IPAM
	// pool if there is some error in any step past the point the IPs were
	// assigned via the IPAM manager.
	// this needs to be done only when ipsAllocated is set to true (the case where
	// we truly have assigned podIPs in this call) AND when there is no error in
	// the rest of the functionality. It is important to use a
	// named return variable for defer to work correctly.
	defer func() {
		if releaseIPs && err != nil {
			if relErr := pa.IPAllocator.ReleaseIPs(podAnnotation.IPs); relErr != nil {
				klog.Errorf("Error when releasing IPs %v: %w", StringIPNets(podAnnotation.IPs), err)
			} else {
				klog.Infof("Released IPs %v", StringIPNets(podAnnotation.IPs))
			}
		}
	}()

	if len(podAnnotation.IPs) == 0 {
		needsAnnotationUpdate = true

		if network != nil && network.IPRequest != nil {
			klog.V(5).Infof("Will use requested IP addresses %s for pod %s", network.IPRequest, podDesc)
			podAnnotation.IPs, err = ParseIPNets(network.IPRequest)
			if err != nil {
				return nil, false, err
			}
		}
	}

	if pa.IPAllocator != nil {
		if len(podAnnotation.IPs) > 0 {
			if err = pa.IPAllocator.AllocateIPs(podAnnotation.IPs); err != nil && !errors.Is(err, errAllocated{}) {
				err = fmt.Errorf("failed to ensure IPs %v allocated for already annotated pod %s: %w",
					StringIPNets(podAnnotation.IPs), podDesc, err)
				if !reallocateOnError {
					return nil, false, err
				}
				klog.Warning(err.Error())
				needsAnnotationUpdate = true
				podAnnotation.IPs = nil
			}
		}

		if len(podAnnotation.IPs) == 0 {
			podAnnotation.IPs, err = pa.IPAllocator.AllocateNextIPs()
			if err != nil {
				return nil, false, fmt.Errorf("failed to assign pod addresses for pod %s: %w", podDesc, err)
			}

			klog.V(5).Infof("Allocated IP addresses %v for pod %s", StringIPNets(podAnnotation.IPs), podDesc)
		}

		releaseIPs = true
	}

	if needsAnnotationUpdate {
		// handle mac address
		if network != nil && network.MacRequest != "" {
			podAnnotation.MAC, err = net.ParseMAC(network.MacRequest)
		} else if len(podAnnotation.IPs) > 0 {
			podAnnotation.MAC = IPAddrToHWAddr(podAnnotation.IPs[0].IP)
		} else {
			podAnnotation.MAC, err = generateRandMAC()
		}
		if err != nil {
			return nil, false, err
		}
		klog.V(5).Infof("Allocated mac address %s for pod %s", podAnnotation.MAC.String(), podDesc)

		// handle routes & gateways
		nodeSubnets, err := pa.IPAllocator.GetSubnets()
		if err != nil {
			return nil, false, err
		}
		err = addRoutesGatewayIP(pod, pa.NetInfo, network, podAnnotation, nodeSubnets)
		if err != nil {
			return nil, false, err
		}
		klog.V(5).Infof("Allocated gateways %s for pod %s", podAnnotation.Gateways, podDesc)

		// update annotation
		annoStart := time.Now()
		err = pa.PodAnnotationUpdate(pod, podAnnotation, nadName)
		podAnnoTime := time.Since(annoStart)
		klog.Infof("[%s] pod annotation time took %v", podDesc, podAnnoTime)
		if err != nil {
			return nil, false, err
		}
	}

	return podAnnotation, needsAnnotationUpdate, nil
}

// GenerateRandMAC generates a random unicast and locally administered MAC address.
// LOOTED FROM https://github.com/cilium/cilium/blob/v1.12.6/pkg/mac/mac.go#L106
func generateRandMAC() (net.HardwareAddr, error) {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("unable to retrieve 6 rnd bytes: %s", err)
	}

	// Set locally administered addresses bit and reset multicast bit
	buf[0] = (buf[0] | 0x02) & 0xfe

	return buf, nil
}

func addRoutesGatewayIP(pod *v1.Pod, netinfo NetInfo, network *nadapi.NetworkSelectionElement, podAnnotation *PodAnnotation, nodeSubnets []*net.IPNet) error {
	if netinfo.IsSecondary() {
		// for secondary network, see if its network-attachment's annotation has default-route key.
		// If present, then we need to add default route for it
		podAnnotation.Gateways = append(podAnnotation.Gateways, network.GatewayRequest...)
		topoType := netinfo.TopologyType()
		switch topoType {
		case types.Layer2Topology, types.LocalnetTopology:
			// no route needed for directly connected subnets
			return nil
		case types.Layer3Topology:
			for _, podIfAddr := range podAnnotation.IPs {
				isIPv6 := utilnet.IsIPv6CIDR(podIfAddr)
				nodeSubnet, err := MatchFirstIPNetFamily(isIPv6, nodeSubnets)
				if err != nil {
					return err
				}
				gatewayIPnet := GetNodeGatewayIfAddr(nodeSubnet)
				for _, clusterSubnet := range netinfo.Subnets() {
					if isIPv6 == utilnet.IsIPv6CIDR(clusterSubnet.CIDR) {
						podAnnotation.Routes = append(podAnnotation.Routes, PodRoute{
							Dest:    clusterSubnet.CIDR,
							NextHop: gatewayIPnet.IP,
						})
					}
				}
			}
			return nil
		}
		return fmt.Errorf("topology type %s not supported", topoType)
	}

	// if there are other network attachments for the pod, then check if those network-attachment's
	// annotation has default-route key. If present, then we need to skip adding default route for
	// OVN interface
	networks, err := GetK8sPodAllNetworkSelections(pod)
	if err != nil {
		return fmt.Errorf("error while getting network attachment definition for [%s/%s]: %v",
			pod.Namespace, pod.Name, err)
	}
	otherDefaultRouteV4 := false
	otherDefaultRouteV6 := false
	for _, network := range networks {
		for _, gatewayRequest := range network.GatewayRequest {
			if utilnet.IsIPv6(gatewayRequest) {
				otherDefaultRouteV6 = true
			} else {
				otherDefaultRouteV4 = true
			}
		}
	}

	for _, podIfAddr := range podAnnotation.IPs {
		isIPv6 := utilnet.IsIPv6CIDR(podIfAddr)
		nodeSubnet, err := MatchFirstIPNetFamily(isIPv6, nodeSubnets)
		if err != nil {
			return err
		}

		gatewayIPnet := GetNodeGatewayIfAddr(nodeSubnet)

		otherDefaultRoute := otherDefaultRouteV4
		if isIPv6 {
			otherDefaultRoute = otherDefaultRouteV6
		}
		var gatewayIP net.IP
		if otherDefaultRoute {
			for _, clusterSubnet := range config.Default.ClusterSubnets {
				if isIPv6 == utilnet.IsIPv6CIDR(clusterSubnet.CIDR) {
					podAnnotation.Routes = append(podAnnotation.Routes, PodRoute{
						Dest:    clusterSubnet.CIDR,
						NextHop: gatewayIPnet.IP,
					})
				}
			}
			for _, serviceSubnet := range config.Kubernetes.ServiceCIDRs {
				if isIPv6 == utilnet.IsIPv6CIDR(serviceSubnet) {
					podAnnotation.Routes = append(podAnnotation.Routes, PodRoute{
						Dest:    serviceSubnet,
						NextHop: gatewayIPnet.IP,
					})
				}
			}
		} else {
			gatewayIP = gatewayIPnet.IP
		}

		if gatewayIP != nil {
			podAnnotation.Gateways = append(podAnnotation.Gateways, gatewayIP)
		}
	}
	return nil
}

func UpdatePodAnnotationWithRetry(podLister listers.PodLister, kube kube.Interface, pod *v1.Pod, podInfo *PodAnnotation, nadName string) error {
	resultErr := retry.RetryOnConflict(OvnConflictBackoff, func() error {
		// Informer cache should not be mutated, so get a copy of the object
		pod, err := podLister.Pods(pod.Namespace).Get(pod.Name)
		if err != nil {
			return err
		}

		cpod := pod.DeepCopy()
		cpod.Annotations, err = MarshalPodAnnotation(cpod.Annotations, podInfo, nadName)
		if err != nil {
			return err
		}
		return kube.UpdatePod(cpod)
	})
	if resultErr != nil {
		return fmt.Errorf("failed to update annotation on pod %s/%s: %v", pod.Namespace, pod.Name, resultErr)
	}
	return nil
}
