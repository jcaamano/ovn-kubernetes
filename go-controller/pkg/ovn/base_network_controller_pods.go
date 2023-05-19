package ovn

import (
	"fmt"
	"net"
	"time"

	nadapi "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ipallocator"
	logicalswitchmanager "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/logical_switch_manager"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/pkg/errors"
	kapi "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/ovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
)

func (bnc *BaseNetworkController) allocatePodIPs(pod *kapi.Pod,
	annotations *util.PodAnnotation, nadName string) (expectedLogicalPortName string, err error) {
	switchName, err := bnc.getExpectedSwitchName(pod)
	if err != nil {
		return "", err
	}
	if !util.PodScheduled(pod) || util.PodWantsHostNetwork(pod) || util.PodCompleted(pod) {
		return "", nil
	}
	// skip nodes that are not running ovnk (inferred from host subnets)
	if bnc.lsManager.IsNonHostSubnetSwitch(switchName) {
		return "", nil
	}
	expectedLogicalPortName = bnc.GetLogicalPortName(pod, nadName)
	// it is possible to try to add a pod here that has no node. For example if a pod was deleted with
	// a finalizer, and then the node was removed. In this case the pod will still exist in a running state.
	// Terminating pods should still have network connectivity for pre-stop hooks or termination grace period
	if _, err := bnc.watchFactory.GetNode(pod.Spec.NodeName); kerrors.IsNotFound(err) &&
		bnc.lsManager.GetSwitchSubnets(switchName) == nil {
		if util.PodTerminating(pod) {
			klog.Infof("Ignoring IP allocation for terminating pod: %s/%s, on deleted "+
				"node: %s", pod.Namespace, pod.Name, pod.Spec.NodeName)
			return expectedLogicalPortName, nil
		} else if bnc.doesNetworkRequireIPAM() {
			// unknown condition how we are getting a non-terminating pod without a node here
			klog.Errorf("Pod IP allocation found for a non-existent node in API with unknown "+
				"condition. Pod: %s/%s, node: %s", pod.Namespace, pod.Name, pod.Spec.NodeName)
		}
	}
	if err := bnc.waitForNodeLogicalSwitchSubnetsInCache(switchName); err != nil {
		return expectedLogicalPortName, fmt.Errorf("failed to wait for switch %s to be added to cache. IP allocation may fail!",
			switchName)
	}
	if err = bnc.lsManager.AllocateIPs(switchName, annotations.IPs); err != nil {
		if err == ipallocator.ErrAllocated {
			// already allocated: log an error but not stop syncPod from continuing
			klog.Errorf("Already allocated IPs: %s for pod: %s on switchName: %s",
				util.JoinIPNetIPs(annotations.IPs, " "), expectedLogicalPortName,
				switchName)
		} else {
			return expectedLogicalPortName, fmt.Errorf("couldn't allocate IPs: %s for pod: %s on switch: %s"+
				" error: %v", util.JoinIPNetIPs(annotations.IPs, " "), expectedLogicalPortName,
				switchName, err)
		}
	}
	return expectedLogicalPortName, nil
}

func (bnc *BaseNetworkController) deleteStaleLogicalSwitchPorts(expectedLogicalPorts map[string]bool) error {
	var switchNames []string

	// get all switches that Pod logical port would be reside on.
	topoType := bnc.TopologyType()
	if !bnc.IsSecondary() || topoType == ovntypes.Layer3Topology {
		// for default network and layer3 topology type networks, get all local zone node switches
		nodes, err := bnc.GetLocalZoneNodes()
		if err != nil {
			return fmt.Errorf("failed to get nodes: %v", err)
		}

		switchNames = make([]string, 0, len(nodes))
		for _, n := range nodes {
			// skip nodes that are not running ovnk (inferred from host subnets)
			switchName := bnc.GetNetworkScopedName(n.Name)
			if bnc.lsManager.IsNonHostSubnetSwitch(switchName) {
				continue
			}
			switchNames = append(switchNames, switchName)
		}
	} else if topoType == ovntypes.Layer2Topology {
		switchNames = []string{bnc.GetNetworkScopedName(ovntypes.OVNLayer2Switch)}
	} else if topoType == ovntypes.LocalnetTopology {
		switchNames = []string{bnc.GetNetworkScopedName(ovntypes.OVNLocalnetSwitch)}
	} else {
		return fmt.Errorf("topology type %s not supported", topoType)
	}

	return bnc.deleteStaleLogicalSwitchPortsOnSwitches(switchNames, expectedLogicalPorts)
}

func (bnc *BaseNetworkController) deleteStaleLogicalSwitchPortsOnSwitches(switchNames []string,
	expectedLogicalPorts map[string]bool) error {
	var ops []ovsdb.Operation
	var err error
	for _, switchName := range switchNames {
		p := func(item *nbdb.LogicalSwitchPort) bool {
			return item.ExternalIDs["pod"] == "true" && !expectedLogicalPorts[item.Name]
		}
		sw := nbdb.LogicalSwitch{
			Name: switchName,
		}

		ops, err = libovsdbops.DeleteLogicalSwitchPortsWithPredicateOps(bnc.nbClient, ops, &sw, p)
		if err != nil {
			return fmt.Errorf("could not generate ops to delete stale ports from logical switch %s (%+v)", switchName, err)
		}
	}

	_, err = libovsdbops.TransactAndCheck(bnc.nbClient, ops)
	if err != nil {
		return fmt.Errorf("could not remove stale logicalPorts from switches for network %s (%+v)", bnc.GetNetworkName(), err)
	}
	return nil
}

// lookupPortUUIDAndSwitchName will use libovsdb to locate the logical switch port uuid as well as the logical switch
// that owns such port (aka nodeName), based on the logical port name.
func (bnc *BaseNetworkController) lookupPortUUIDAndSwitchName(logicalPort string) (portUUID string, logicalSwitch string, err error) {
	lsp := &nbdb.LogicalSwitchPort{Name: logicalPort}
	lsp, err = libovsdbops.GetLogicalSwitchPort(bnc.nbClient, lsp)
	if err != nil {
		return "", "", err
	}
	p := func(item *nbdb.LogicalSwitch) bool {
		for _, currPortUUID := range item.Ports {
			if currPortUUID == lsp.UUID {
				return true
			}
		}
		return false
	}
	nodeSwitches, err := libovsdbops.FindLogicalSwitchesWithPredicate(bnc.nbClient, p)
	if err != nil {
		return "", "", fmt.Errorf("failed to get node logical switch for logical port %s (%s): %w", logicalPort, lsp.UUID, err)
	}
	if len(nodeSwitches) != 1 {
		return "", "", fmt.Errorf("found %d node logical switch for logical port %s (%s)", len(nodeSwitches), logicalPort, lsp.UUID)
	}
	return lsp.UUID, nodeSwitches[0].Name, nil
}

func (bnc *BaseNetworkController) deletePodLogicalPort(pod *kapi.Pod, portInfo *lpInfo,
	nadName string) (*lpInfo, error) {
	var portUUID, switchName, logicalPort string
	var podIfAddrs []*net.IPNet

	expectedSwitchName, err := bnc.getExpectedSwitchName(pod)
	if err != nil {
		return nil, err
	}

	podDesc := fmt.Sprintf("pod %s/%s/%s", nadName, pod.Namespace, pod.Name)
	logicalPort = bnc.GetLogicalPortName(pod, nadName)
	if portInfo == nil {
		// If ovnkube-master restarts, it is also possible the Pod's logical switch port
		// is not re-added into the cache. Delete logical switch port anyway.
		annotation, err := util.UnmarshalPodAnnotation(pod.Annotations, nadName)
		if err != nil {
			if util.IsAnnotationNotSetError(err) {
				// if the annotation doesn’t exist, that’s not an error. It means logical port does not need to be deleted.
				klog.V(5).Infof("No annotations on %s, no need to delete its logical port: %s", podDesc, logicalPort)
				return nil, nil
			}
			return nil, fmt.Errorf("unable to unmarshal pod annotations for %s: %w", podDesc, err)
		}

		// Since portInfo is not available, use ovn to locate the logical switch (named after the node name) for the logical port.
		portUUID, switchName, err = bnc.lookupPortUUIDAndSwitchName(logicalPort)
		if err != nil {
			if err != libovsdbclient.ErrNotFound {
				return nil, fmt.Errorf("unable to locate portUUID+switchName for %s: %w", podDesc, err)
			}
			// The logical port no longer exists in OVN. The caller expects this function to be idem-potent,
			// so the proper action to take is to use an empty uuid and extract the node name from the pod spec.
			portUUID = ""
			switchName = expectedSwitchName
		}
		podIfAddrs = annotation.IPs

		klog.Warningf("No cached port info for deleting %s. Using logical switch %s port uuid %s and addrs %v",
			podDesc, switchName, portUUID, podIfAddrs)
	} else {
		portUUID = portInfo.uuid
		switchName = portInfo.logicalSwitch
		podIfAddrs = portInfo.ips
	}

	// Sanity check
	if switchName != expectedSwitchName {
		klog.Errorf("Deleting %s expecting switch name: %s, OVN DB has switch name %s for port uuid %s",
			podDesc, expectedSwitchName, switchName, portUUID)
	}

	shouldRelease := true
	// check to make sure no other pods are using this IP before we try to release it if this is a completed pod.
	if util.PodCompleted(pod) {
		if shouldRelease, err = bnc.lsManager.ConditionalIPRelease(switchName, podIfAddrs, func() (bool, error) {

			// Ignore pods on other switches
			if expectedSwitchName != switchName {
				return true, nil
			}

			canRelease, err := bnc.canReleasePodIPs(podIfAddrs)
			if err != nil {
				return false, fmt.Errorf("unable to determine if completed pod IP is in use by another pod. "+
					"Will not release pod %s/%s IP: %#v from allocator. %v", pod.Namespace, pod.Name, podIfAddrs, err)
			}

			if !canRelease {
				klog.Infof("Will not release IP address: %s for %s. Detected another pod using it."+
					" using this IP: %s/%s", util.JoinIPNetIPs(podIfAddrs, " "), podDesc)
				return false, nil
			}

			klog.Infof("Releasing IPs for Completed pod: %s/%s, ips: %s", pod.Namespace, pod.Name,
				util.JoinIPNetIPs(podIfAddrs, " "))
			return true, nil
		}); err != nil {
			return nil, fmt.Errorf("cannot determine if IPs are safe to release for completed pod: %s: %w", podDesc, err)
		}
	}

	var allOps, ops []ovsdb.Operation

	// if the ip is in use by another pod we should not try to remove it from the address set
	if shouldRelease {
		if ops, err = bnc.deletePodFromNamespace(pod.Namespace,
			podIfAddrs, portUUID); err != nil {
			return nil, fmt.Errorf("unable to delete pod %s from namespace: %w", podDesc, err)
		}
		allOps = append(allOps, ops...)
	}
	ops, err = bnc.delLSPOps(logicalPort, switchName, portUUID)
	// Tolerate cases where logical switch of the logical port no longer exist in OVN.
	if err != nil && !errors.Is(err, libovsdbclient.ErrNotFound) {
		return nil, fmt.Errorf("failed to create delete ops for the lsp: %s: %s", logicalPort, err)
	}
	allOps = append(allOps, ops...)

	recordOps, txOkCallBack, _, err := bnc.AddConfigDurationRecord("pod", pod.Namespace, pod.Name)
	if err != nil {
		klog.Errorf("Failed to record config duration: %v", err)
	}
	allOps = append(allOps, recordOps...)

	_, err = libovsdbops.TransactAndCheck(bnc.nbClient, allOps)
	if err != nil {
		return nil, fmt.Errorf("cannot delete logical switch port %s, %v", logicalPort, err)
	}
	txOkCallBack()

	// do not remove SNATs/GW routes/IPAM for an IP address unless we have validated no other pod is using it
	if !shouldRelease {
		return nil, nil
	}

	pInfo := lpInfo{
		name:          logicalPort,
		uuid:          portUUID,
		logicalSwitch: switchName,
		ips:           podIfAddrs,
	}
	return &pInfo, nil
}

func (bnc *BaseNetworkController) findPodWithIPAddresses(needleIPs []net.IP) (*kapi.Pod, error) {
	allPods, err := bnc.watchFactory.GetAllPods()
	if err != nil {
		return nil, fmt.Errorf("unable to get pods: %w", err)
	}

	// iterate through all pods
	for _, p := range allPods {
		if util.PodCompleted(p) || util.PodWantsHostNetwork(p) || !util.PodScheduled(p) {
			continue
		}
		// check if the pod addresses match in the OVN annotation
		haystackPodAddrs, err := util.GetPodIPsOfNetwork(p, bnc.NetInfo)
		if err != nil {
			continue
		}

		for _, haystackPodAddr := range haystackPodAddrs {
			for _, needleIP := range needleIPs {
				if haystackPodAddr.Equal(needleIP) {
					return p, nil
				}
			}
		}
	}

	return nil, nil
}

// canReleasePodIPs checks if the podIPs can be released or not.
func (bnc *BaseNetworkController) canReleasePodIPs(podIfAddrs []*net.IPNet) (bool, error) {
	// in certain configurations IP allocation is handled by cluster manager so
	// we can locally release the IPs without checking
	if !bnc.handlesPodIPAllocation() {
		return true, nil
	}

	var needleIPs []net.IP
	for _, podIPNet := range podIfAddrs {
		needleIPs = append(needleIPs, podIPNet.IP)
	}
	collidingPod, err := bnc.findPodWithIPAddresses(needleIPs)
	if err != nil {
		return false, fmt.Errorf("unable to determine if pod IPs: %#v are in use by another pod :%w", podIfAddrs, err)

	}

	if collidingPod != nil {
		klog.Infof("Should not release IP address: %s. Detected another pod"+
			" using this IP: %s/%s", util.JoinIPNetIPs(podIfAddrs, " "), collidingPod.Namespace, collidingPod.Name)
		return false, nil
	}

	return true, nil
}

func (bnc *BaseNetworkController) releasePodIPs(pInfo *lpInfo) error {
	if err := bnc.lsManager.ReleaseIPs(pInfo.logicalSwitch, pInfo.ips); err != nil {
		if !errors.Is(err, logicalswitchmanager.SwitchNotFound) {
			return fmt.Errorf("cannot release IPs of port %s on switch %s: %w", pInfo.name, pInfo.logicalSwitch, err)
		}
		klog.Warningf("Ignoring release IPs failure of port %s on switch %s: %w", pInfo.name, pInfo.logicalSwitch, err)
	}
	return nil
}

func (bnc *BaseNetworkController) waitForNodeLogicalSwitch(switchName string) (*nbdb.LogicalSwitch, error) {
	// Wait for the node logical switch to be created by the ClusterController and be present
	// in libovsdb's cache. The node switch will be created when the node's logical network infrastructure
	// is created by the node watch
	ls := &nbdb.LogicalSwitch{Name: switchName}
	if err := wait.PollImmediate(30*time.Millisecond, 30*time.Second, func() (bool, error) {
		if subnets := bnc.lsManager.GetSwitchSubnets(switchName); subnets == nil {
			return false, fmt.Errorf("error getting logical switch %s: %s", switchName, "switch not in logical switch cache")
		}
		return true, nil
	}); err != nil {
		return nil, fmt.Errorf("timed out waiting for logical switch in logical switch cache %q subnet: %v", switchName, err)
	}
	return ls, nil
}

func (bnc *BaseNetworkController) waitForNodeLogicalSwitchSubnetsInCache(switchName string) error {
	// Wait for the node logical switch with IPAM to be created by the ClusterController
	// The node switch will be created when the node's logical network infrastructure
	// is created by the node watch.
	// This function is only invoked when IPAM is required.
	var subnets []*net.IPNet
	if err := wait.PollImmediate(30*time.Millisecond, 30*time.Second, func() (bool, error) {
		subnets = bnc.lsManager.GetSwitchSubnets(switchName)
		return subnets != nil, nil
	}); err != nil {
		return fmt.Errorf("timed out waiting for logical switch %q subnet: %v", switchName, err)
	}
	return nil
}

// podExpectedInLogicalCache returns true if pod should be added to oc.logicalPortCache.
// For some pods, like hostNetwork pods, overlay node pods, or completed pods waiting for them to be added
// to oc.logicalPortCache will never succeed.
func (bnc *BaseNetworkController) podExpectedInLogicalCache(pod *kapi.Pod) bool {
	switchName, err := bnc.getExpectedSwitchName(pod)
	if err != nil {
		return false
	}
	return !util.PodWantsHostNetwork(pod) && !bnc.lsManager.IsNonHostSubnetSwitch(switchName) && !util.PodCompleted(pod)
}

func (bnc *BaseNetworkController) getExpectedSwitchName(pod *kapi.Pod) (string, error) {
	switchName := pod.Spec.NodeName
	if bnc.IsSecondary() {
		topoType := bnc.TopologyType()
		switch topoType {
		case ovntypes.Layer3Topology:
			switchName = bnc.GetNetworkScopedName(pod.Spec.NodeName)
		case ovntypes.Layer2Topology:
			switchName = bnc.GetNetworkScopedName(ovntypes.OVNLayer2Switch)
		case ovntypes.LocalnetTopology:
			switchName = bnc.GetNetworkScopedName(ovntypes.OVNLocalnetSwitch)
		default:
			return "", fmt.Errorf("topology type %s not supported", topoType)
		}
	}
	return switchName, nil
}

func (bnc *BaseNetworkController) addLogicalPortToNetwork(pod *kapi.Pod, nadName string,
	network *nadapi.NetworkSelectionElement) (ops []ovsdb.Operation,
	lsp *nbdb.LogicalSwitchPort, podAnnotation *util.PodAnnotation, newlyCreatedPort bool, err error) {
	var ls *nbdb.LogicalSwitch

	podDesc := fmt.Sprintf("%s/%s/%s", nadName, pod.Namespace, pod.Name)
	switchName, err := bnc.getExpectedSwitchName(pod)
	if err != nil {
		return nil, nil, nil, false, err
	}
	// it is possible to try to add a pod here that has no node. For example if a pod was deleted with
	// a finalizer, and then the node was removed. In this case the pod will still exist in a running state.
	// Terminating pods should still have network connectivity for pre-stop hooks or termination grace period
	// We cannot wire a pod that has no node/switch, so retry again later
	if _, err := bnc.watchFactory.GetNode(pod.Spec.NodeName); kerrors.IsNotFound(err) &&
		bnc.lsManager.GetSwitchSubnets(switchName) == nil && bnc.doesNetworkRequireIPAM() {
		podState := "unknown"
		if util.PodTerminating(pod) {
			podState = "terminating"
		}
		return nil, nil, nil, false, fmt.Errorf("[%s/%s] Non-existent node: %s in API for pod with %s state",
			pod.Namespace, pod.Name, pod.Spec.NodeName, podState)
	}

	ls, err = bnc.waitForNodeLogicalSwitch(switchName)
	if err != nil {
		return nil, nil, nil, false, err
	}

	portName := bnc.GetLogicalPortName(pod, nadName)
	klog.Infof("[%s] creating logical port %s for pod on switch %s", podDesc, portName, switchName)

	var addresses []string
	lspExist := false

	// Check if the pod's logical switch port already exists. If it
	// does don't re-add the port to OVN as this will change its
	// UUID and and the port cache, address sets, and port groups
	// will still have the old UUID.
	lsp = &nbdb.LogicalSwitchPort{Name: portName}
	existingLSP, err := libovsdbops.GetLogicalSwitchPort(bnc.nbClient, lsp)
	if err != nil && err != libovsdbclient.ErrNotFound {
		return nil, nil, nil, false, fmt.Errorf("unable to get the lsp %s from the nbdb: %s", portName, err)
	}
	lspExist = err != libovsdbclient.ErrNotFound

	// Sanity check. If port exists, it should be in the logical switch obtained from the pod spec.
	if lspExist {
		portFound := false
		ls, err = libovsdbops.GetLogicalSwitch(bnc.nbClient, ls)
		if err != nil {
			return nil, nil, nil, false, fmt.Errorf("[%s] unable to find logical switch %s in NBDB",
				podDesc, switchName)
		}
		for _, currPortUUID := range ls.Ports {
			if currPortUUID == existingLSP.UUID {
				portFound = true
				break
			}
		}
		if !portFound {
			// This should never happen and indicates we failed to clean up an LSP for a pod that was recreated
			return nil, nil, nil, false, fmt.Errorf("[%s] failed to locate existing logical port %s (%s) in logical switch %s",
				podDesc, existingLSP.Name, existingLSP.UUID, switchName)
		}
	}

	lsp.Options = make(map[string]string)
	// Unique identifier to distinguish interfaces for recreated pods, also set by ovnkube-node
	// ovn-controller will claim the OVS interface only if external_ids:iface-id
	// matches with the Port_Binding.logical_port and external_ids:iface-id-ver matches
	// with the Port_Binding.options:iface-id-ver. This is not mandatory.
	// If Port_binding.options:iface-id-ver is not set, then OVS
	// Interface.external_ids:iface-id-ver if set is ignored.
	// Don't set iface-id-ver for already existing LSP if it wasn't set before,
	// because the corresponding OVS port may not have it set
	// (then ovn-controller won't bind the interface).
	// May happen on upgrade, because ovnkube-node doesn't update
	// existing OVS interfaces with new iface-id-ver option.
	if !lspExist || len(existingLSP.Options["iface-id-ver"]) != 0 {
		lsp.Options["iface-id-ver"] = string(pod.UID)
	}
	// Bind the port to the node's chassis; prevents ping-ponging between
	// chassis if ovnkube-node isn't running correctly and hasn't cleared
	// out iface-id for an old instance of this pod, and the pod got
	// rescheduled.
	lsp.Options["requested-chassis"] = pod.Spec.NodeName

	podAnnotation, annotationUpdated, err := bnc.allocateIPs(pod, existingLSP, nadName, network)
	if err != nil {
		return nil, nil, nil, false, err
	}

	// set addresses on the port
	// LSP addresses in OVN are a single space-separated value
	addresses = []string{podAnnotation.MAC.String()}
	for _, podIfAddr := range podAnnotation.IPs {
		addresses[0] = addresses[0] + " " + podIfAddr.IP.String()
	}

	lsp.Addresses = addresses

	// add external ids
	lsp.ExternalIDs = map[string]string{"namespace": pod.Namespace, "pod": "true"}
	if bnc.IsSecondary() {
		lsp.ExternalIDs[ovntypes.NetworkExternalID] = bnc.GetNetworkName()
		lsp.ExternalIDs[ovntypes.NADExternalID] = nadName
		lsp.ExternalIDs[ovntypes.TopologyExternalID] = bnc.TopologyType()
	}

	// CNI depends on the flows from port security, delay setting it until end
	lsp.PortSecurity = addresses

	ops, err = libovsdbops.CreateOrUpdateLogicalSwitchPortsOnSwitchOps(bnc.nbClient, nil, ls, lsp)
	if err != nil {
		return nil, nil, nil, false,
			fmt.Errorf("error creating logical switch port %+v on switch %+v: %+v", *lsp, *ls, err)
	}

	return ops, lsp, podAnnotation, annotationUpdated && !lspExist, nil
}

func (bnc *BaseNetworkController) updatePodAnnotationWithRetry(origPod *kapi.Pod, podInfo *util.PodAnnotation, nadName string) error {
	resultErr := retry.RetryOnConflict(util.OvnConflictBackoff, func() error {
		// Informer cache should not be mutated, so get a copy of the object
		pod, err := bnc.watchFactory.GetPod(origPod.Namespace, origPod.Name)
		if err != nil {
			return err
		}

		cpod := pod.DeepCopy()
		cpod.Annotations, err = util.MarshalPodAnnotation(cpod.Annotations, podInfo, nadName)
		if err != nil {
			return err
		}
		return bnc.kube.UpdatePod(cpod)
	})
	if resultErr != nil {
		return fmt.Errorf("failed to update annotation on pod %s/%s: %v", origPod.Namespace, origPod.Name, resultErr)
	}
	return nil
}

// Given a logical switch port and the switch on which it is scheduled, get all
// addresses currently assigned to it including subnet masks.
func (bnc *BaseNetworkController) getPortAddresses(switchName string, existingLSP *nbdb.LogicalSwitchPort) (net.HardwareAddr, []*net.IPNet, error) {
	podMac, podIPs, err := util.ExtractPortAddresses(existingLSP)
	if err != nil {
		return nil, nil, err
	} else if podMac == nil || len(podIPs) == 0 {
		return nil, nil, nil
	}

	var podIPNets []*net.IPNet

	nodeSubnets := bnc.lsManager.GetSwitchSubnets(switchName)

	for _, ip := range podIPs {
		for _, subnet := range nodeSubnets {
			if subnet.Contains(ip) {
				podIPNets = append(podIPNets,
					&net.IPNet{
						IP:   ip,
						Mask: subnet.Mask,
					})
				break
			}
		}
	}
	return podMac, podIPNets, nil
}

// delLSPOps returns the ovsdb operations required to delete the given logical switch port (LSP)
func (bnc *BaseNetworkController) delLSPOps(logicalPort, switchName,
	lspUUID string) ([]ovsdb.Operation, error) {
	lsw := nbdb.LogicalSwitch{
		Name: switchName,
	}
	lsp := nbdb.LogicalSwitchPort{
		UUID: lspUUID,
		Name: logicalPort,
	}
	ops, err := libovsdbops.DeleteLogicalSwitchPortsOps(bnc.nbClient, nil, &lsw, &lsp)
	if err != nil {
		return nil, fmt.Errorf("error deleting logical switch port %+v from switch %+v: %w", lsp, lsw, err)
	}

	return ops, nil
}

func (bnc *BaseNetworkController) deletePodFromNamespace(ns string, podIfAddrs []*net.IPNet, portUUID string) ([]ovsdb.Operation, error) {
	// for secondary network, namespace may be not managed
	nsInfo, nsUnlock := bnc.getNamespaceLocked(ns, true)
	if nsInfo == nil {
		return nil, nil
	}
	defer nsUnlock()
	var ops []ovsdb.Operation
	var err error
	if nsInfo.addressSet != nil {
		if ops, err = nsInfo.addressSet.DeleteIPsReturnOps(createIPAddressSlice(podIfAddrs)); err != nil {
			return nil, err
		}
	}

	// Remove the port from the multicast allow policy.
	if bnc.multicastSupport && nsInfo.multicastEnabled && len(portUUID) > 0 {
		if err = bnc.podDeleteAllowMulticastPolicy(ns, portUUID); err != nil {
			return nil, err
		}
	}

	return ops, nil
}

// isPodScheduledinLocalZone returns true if
//   - bnc.localZoneNodes map is nil or
//   - if the pod.Spec.NodeName is in the bnc.localZoneNodes map
//
// false otherwise.
func (bnc *BaseNetworkController) isPodScheduledinLocalZone(pod *kapi.Pod) bool {
	isLocalZonePod := true

	if bnc.localZoneNodes != nil {
		if util.PodScheduled(pod) {
			_, isLocalZonePod = bnc.localZoneNodes.Load(pod.Spec.NodeName)
		} else {
			isLocalZonePod = false
		}
	}

	return isLocalZonePod
}

// WatchPods starts the watching of the Pod resource and calls back the appropriate handler logic
func (bnc *BaseNetworkController) WatchPods() error {
	if bnc.podHandler != nil {
		return nil
	}

	handler, err := bnc.retryPods.WatchResource()
	if err == nil {
		bnc.podHandler = handler
	}
	return err
}

func (bnc *BaseNetworkController) handlesPodIPAllocation() bool {
	// the controller is in charge of pod IP allocation except L2 topologies
	// with IPAM on interconnect
	switch bnc.NetInfo.TopologyType() {
	case ovntypes.Layer2Topology, ovntypes.LocalnetTopology:
		return !config.OVNKubernetesFeature.EnableInterconnect || !bnc.doesNetworkRequireIPAM()
	}
	return true
}

// allocateIPs and update the corresponding pod annotation
func (bnc *BaseNetworkController) allocateIPs(pod *kapi.Pod, lsp *nbdb.LogicalSwitchPort, nadName string, network *nadapi.NetworkSelectionElement) (*util.PodAnnotation, bool, error) {
	podAnnotation, err := util.UnmarshalPodAnnotation(pod.Annotations, nadName)

	// In certain configurations, pod IP allocation is handled from cluster
	// manager so wait for it to allocate the IPs
	if !bnc.handlesPodIPAllocation() {
		if err != nil || len(podAnnotation.IPs) == 0 {
			return nil, false, fmt.Errorf("failed to get IPs for pod %s/%s/%s, cluster manager might have not allocated them yet: %w",
				nadName, pod.Namespace, pod.Name, err)
		}
	}

	switchName, err := bnc.getExpectedSwitchName(pod)
	if err != nil {
		return nil, false, err
	}

	var reallocateOnError bool
	if lsp != nil && (podAnnotation == nil || len(podAnnotation.IPs) == 0) {
		mac, ips, err := bnc.getPortAddresses(switchName, lsp)
		if err != nil {
			return nil, false, fmt.Errorf("failed to get pod addresses for pod %s/%s/%s on node %s, err: %v",
				nadName, pod.Namespace, pod.Name, switchName, err)
		}
		network.MacRequest = mac.String()
		network.IPRequest = util.StringIPNets(ips)

		klog.V(5).Infof("Will attempt to use LSP IP addresses %v and mac %s for pod %s/%s/%s",
			network.IPRequest, network.MacRequest, nadName, pod.Namespace, pod.Name)
		reallocateOnError = true
	}

	updatePodAnnotation := func(p *kapi.Pod, a *util.PodAnnotation, nad string) error {
		return util.UpdatePodAnnotationWithRetry(bnc.watchFactory.PodCoreInformer().Lister(), &bnc.kube.Kube, p, a, nad)
	}

	annotator := util.PodAnnotationAllocator{
		NetInfo:             bnc.NetInfo,
		PodAnnotationUpdate: updatePodAnnotation,
	}

	if bnc.doesNetworkRequireIPAM() {
		annotator.IPAllocator = bnc.lsManager.WithSwitch(switchName)
	}

	return annotator.AllocatePodAnnotation(pod, podAnnotation, network, reallocateOnError)
}
