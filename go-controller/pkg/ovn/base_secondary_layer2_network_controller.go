package ovn

import (
	"fmt"
	"net"
	"reflect"
	"strconv"
	"sync"
	"time"

	iputils "github.com/containernetworking/plugins/pkg/ip"
	mnpapi "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/retry"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

// method/structure shared by all layer 2 network controller, including localnet and layer2 network controllres.

type secondaryLayer2NetworkControllerEventHandler struct {
	baseHandler  baseNetworkControllerEventHandler
	watchFactory *factory.WatchFactory
	objType      reflect.Type
	oc           *BaseSecondaryLayer2NetworkController
	syncFunc     func([]interface{}) error
}

// AreResourcesEqual returns true if, given two objects of a known resource type, the update logic for this resource
// type considers them equal and therefore no update is needed. It returns false when the two objects are not considered
// equal and an update needs be executed. This is regardless of how the update is carried out (whether with a dedicated update
// function or with a delete on the old obj followed by an add on the new obj).
func (h *secondaryLayer2NetworkControllerEventHandler) AreResourcesEqual(obj1, obj2 interface{}) (bool, error) {
	return h.baseHandler.areResourcesEqual(h.objType, obj1, obj2)
}

// GetInternalCacheEntry returns the internal cache entry for this object, given an object and its type.
// This is now used only for pods, which will get their the logical port cache entry.
func (h *secondaryLayer2NetworkControllerEventHandler) GetInternalCacheEntry(obj interface{}) interface{} {
	return h.oc.GetInternalCacheEntryForSecondaryNetwork(h.objType, obj)
}

// GetResourceFromInformerCache returns the latest state of the object, given an object key and its type.
// from the informers cache.
func (h *secondaryLayer2NetworkControllerEventHandler) GetResourceFromInformerCache(key string) (interface{}, error) {
	return h.baseHandler.getResourceFromInformerCache(h.objType, h.watchFactory, key)
}

// RecordAddEvent records the add event on this given object.
func (h *secondaryLayer2NetworkControllerEventHandler) RecordAddEvent(obj interface{}) {
	switch h.objType {
	case factory.MultiNetworkPolicyType:
		mnp := obj.(*mnpapi.MultiNetworkPolicy)
		klog.V(5).Infof("Recording add event on multinetwork policy %s/%s", mnp.Namespace, mnp.Name)
		metrics.GetConfigDurationRecorder().Start("multinetworkpolicy", mnp.Namespace, mnp.Name)
	}
}

// RecordUpdateEvent records the udpate event on this given object.
func (h *secondaryLayer2NetworkControllerEventHandler) RecordUpdateEvent(obj interface{}) {
	switch h.objType {
	case factory.MultiNetworkPolicyType:
		mnp := obj.(*mnpapi.MultiNetworkPolicy)
		klog.V(5).Infof("Recording update event on multinetwork policy %s/%s", mnp.Namespace, mnp.Name)
		metrics.GetConfigDurationRecorder().Start("multinetworkpolicy", mnp.Namespace, mnp.Name)
	}
}

// RecordDeleteEvent records the delete event on this given object.
func (h *secondaryLayer2NetworkControllerEventHandler) RecordDeleteEvent(obj interface{}) {
	switch h.objType {
	case factory.MultiNetworkPolicyType:
		mnp := obj.(*mnpapi.MultiNetworkPolicy)
		klog.V(5).Infof("Recording delete event on multinetwork policy %s/%s", mnp.Namespace, mnp.Name)
		metrics.GetConfigDurationRecorder().Start("multinetworkpolicy", mnp.Namespace, mnp.Name)
	}
}

// RecordSuccessEvent records the success event on this given object.
func (h *secondaryLayer2NetworkControllerEventHandler) RecordSuccessEvent(obj interface{}) {
	switch h.objType {
	case factory.MultiNetworkPolicyType:
		mnp := obj.(*mnpapi.MultiNetworkPolicy)
		klog.V(5).Infof("Recording success event on multinetwork policy %s/%s", mnp.Namespace, mnp.Name)
		metrics.GetConfigDurationRecorder().End("multinetworkpolicy", mnp.Namespace, mnp.Name)
	}
}

// RecordErrorEvent records the error event on this given object.
func (h *secondaryLayer2NetworkControllerEventHandler) RecordErrorEvent(obj interface{}, reason string, err error) {
}

// IsResourceScheduled returns true if the given object has been scheduled.
// Only applied to pods for now. Returns true for all other types.
func (h *secondaryLayer2NetworkControllerEventHandler) IsResourceScheduled(obj interface{}) bool {
	return h.baseHandler.isResourceScheduled(h.objType, obj)
}

// AddResource adds the specified object to the cluster according to its type and returns the error,
// if any, yielded during object creation.
// Given an object to add and a boolean specifying if the function was executed from iterateRetryResources
func (h *secondaryLayer2NetworkControllerEventHandler) AddResource(obj interface{}, fromRetryLoop bool) error {
	switch h.objType {
	case factory.NodeType:
		node, ok := obj.(*kapi.Node)
		if !ok {
			return fmt.Errorf("could not cast %T object to *kapi.Node", obj)
		}

		if h.oc.isLocalZoneNode(node) {
			var nodeParams *nodeSyncs
			if fromRetryLoop {
				_, nodeSync := h.oc.addNodeFailed.Load(node.Name)
				_, syncZoneIC := h.oc.syncZoneICFailed.Load(node.Name)
				nodeParams = &nodeSyncs{syncNode: nodeSync, syncZoneIC: syncZoneIC}
			} else {
				nodeParams = &nodeSyncs{syncNode: true, syncZoneIC: config.OVNKubernetesFeature.EnableInterconnect}
			}
			if err := h.oc.addUpdateLocalNodeEvent(node, nodeParams); err != nil {
				klog.Errorf("Node add failed for %s, will try again later: %v",
					node.Name, err)
				return err
			}
		} else {
			if err := h.oc.addUpdateRemoteNodeEvent(node, config.OVNKubernetesFeature.EnableInterconnect); err != nil {
				return err
			}
		}
	case factory.PodType:
		pod, ok := obj.(*kapi.Pod)
		if !ok {
			return fmt.Errorf("could not cast %T object to *knet.Pod", obj)
		}
		// Check if the pod is local zone pod or not.
		if !h.oc.isPodScheduledinLocalZone(pod) {
			return h.oc.ensureRemotePod(pod)
		}
		return h.oc.AddSecondaryNetworkResourceCommon(h.objType, obj)
	}
	return nil
}

// UpdateResource updates the specified object in the cluster to its version in newObj according to its
// type and returns the error, if any, yielded during the object update.
// Given an old and a new object; The inRetryCache boolean argument is to indicate if the given resource
// is in the retryCache or not.
func (h *secondaryLayer2NetworkControllerEventHandler) UpdateResource(oldObj, newObj interface{}, inRetryCache bool) error {
	switch h.objType {
	case factory.NodeType:
		newNode, ok := newObj.(*kapi.Node)
		if !ok {
			return fmt.Errorf("could not cast newObj of type %T to *kapi.Node", newObj)
		}
		oldNode, ok := oldObj.(*kapi.Node)
		if !ok {
			return fmt.Errorf("could not cast oldObj of type %T to *kapi.Node", oldObj)
		}
		if h.oc.isLocalZoneNode(newNode) {
			var nodeSyncsParam *nodeSyncs
			if h.oc.isLocalZoneNode(oldNode) {
				// determine what actually changed in this update
				_, nodeSync := h.oc.addNodeFailed.Load(newNode.Name)
				_, syncZoneIC := h.oc.syncZoneICFailed.Load(newNode.Name)
				syncZoneIC = syncZoneIC || util.NodeNetworkIDAnnotationChanged(oldNode, newNode, h.oc.GetNetworkName())
				nodeSyncsParam = &nodeSyncs{syncNode: nodeSync, syncZoneIC: syncZoneIC}
			} else {
				klog.Infof("Node %s moved from the remote zone %s to local zone.",
					newNode.Name, util.GetNodeZone(oldNode), util.GetNodeZone(newNode))
				// The node is now a local zone node. Trigger a full node sync.
				nodeSyncsParam = &nodeSyncs{syncNode: true, syncClusterRouterPort: true, syncZoneIC: config.OVNKubernetesFeature.EnableInterconnect}
			}

			return h.oc.addUpdateLocalNodeEvent(newNode, nodeSyncsParam)
		} else {
			return h.oc.addUpdateRemoteNodeEvent(newNode, config.OVNKubernetesFeature.EnableInterconnect)
		}
	case factory.PodType:
		pod, ok := newObj.(*kapi.Pod)
		if !ok {
			return fmt.Errorf("could not cast %T object to *knet.Pod", newObj)
		}
		// Check if the pod is local zone pod or not.
		if !h.oc.isPodScheduledinLocalZone(pod) {
			return h.oc.ensureRemotePod(pod)
		}
		return h.oc.UpdateSecondaryNetworkResourceCommon(h.objType, oldObj, newObj, inRetryCache)
	}

	return nil
}

// DeleteResource deletes the object from the cluster according to the delete logic of its resource type.
// Given an object and optionally a cachedObj; cachedObj is the internal cache entry for this object,
// used for now for pods and network policies.
func (h *secondaryLayer2NetworkControllerEventHandler) DeleteResource(obj, cachedObj interface{}) error {
	switch h.objType {
	case factory.NodeType:
		node, ok := obj.(*kapi.Node)
		if !ok {
			return fmt.Errorf("could not cast obj of type %T to *knet.Node", obj)
		}
		return h.oc.deleteNodeEvent(node)

	case factory.PodType:
		pod, ok := obj.(*kapi.Pod)
		if !ok {
			return fmt.Errorf("could not cast %T object to *knet.Pod", obj)
		}
		// Check if the pod is local zone pod or not. If its not a local zone pod, we can ignore it.
		if !h.oc.isPodScheduledinLocalZone(pod) {
			return nil
		}
		fallthrough
	default:
		return h.oc.DeleteSecondaryNetworkResourceCommon(h.objType, obj, cachedObj)
	}
}

func (h *secondaryLayer2NetworkControllerEventHandler) SyncFunc(objs []interface{}) error {
	var syncFunc func([]interface{}) error

	if h.syncFunc != nil {
		// syncFunc was provided explicitly
		syncFunc = h.syncFunc
	} else {
		switch h.objType {
		case factory.PodType:
			syncFunc = h.oc.syncPodsForSecondaryNetwork

		case factory.NamespaceType:
			syncFunc = h.oc.syncNamespaces

		case factory.MultiNetworkPolicyType:
			syncFunc = h.oc.syncMultiNetworkPolicies

		case factory.NodeType:
			syncFunc = h.oc.syncNodes

		default:
			return fmt.Errorf("no sync function for object type %s", h.objType)
		}
	}
	if syncFunc == nil {
		return nil
	}
	return syncFunc(objs)
}

// IsObjectInTerminalState returns true if the given object is a in terminal state.
// This is used now for pods that are either in a PodSucceeded or in a PodFailed state.
func (h *secondaryLayer2NetworkControllerEventHandler) IsObjectInTerminalState(obj interface{}) bool {
	return h.baseHandler.isObjectInTerminalState(h.objType, obj)
}

// BaseSecondaryLayer2NetworkController structure holds per-network fields and network specific
// configuration for secondary layer2/localnet network controller
type BaseSecondaryLayer2NetworkController struct {
	BaseSecondaryNetworkController

	// Node-specific syncMaps used by node event handler
	addNodeFailed    sync.Map
	syncZoneICFailed sync.Map

	//List of nodes which belong to the local zone (stored as a sync map)
	localZoneNodes sync.Map
}

func (oc *BaseSecondaryLayer2NetworkController) initRetryFramework() {
	oc.retryPods = oc.newRetryFramework(factory.PodType)

	if oc.doesNetworkRequireIPAM() {
		oc.retryNamespaces = oc.newRetryFramework(factory.NamespaceType)
		oc.retryNetworkPolicies = oc.newRetryFramework(factory.MultiNetworkPolicyType)
	}

	if config.OVNKubernetesFeature.EnableInterconnect {
		// If interconnect is enabled, we need to be aware as nodes join or
		// leave the zone
		oc.retryNodes = oc.newRetryFramework(factory.NodeType)
	}
}

// newRetryFramework builds and returns a retry framework for the input resource type;
func (oc *BaseSecondaryLayer2NetworkController) newRetryFramework(
	objectType reflect.Type) *retry.RetryFramework {
	eventHandler := &secondaryLayer2NetworkControllerEventHandler{
		baseHandler:  baseNetworkControllerEventHandler{},
		objType:      objectType,
		watchFactory: oc.watchFactory,
		oc:           oc,
		syncFunc:     nil,
	}
	resourceHandler := &retry.ResourceHandler{
		HasUpdateFunc:          hasResourceAnUpdateFunc(objectType),
		NeedsUpdateDuringRetry: needsUpdateDuringRetry(objectType),
		ObjType:                objectType,
		EventHandler:           eventHandler,
	}
	return retry.NewRetryFramework(
		oc.stopChan,
		oc.wg,
		oc.watchFactory,
		resourceHandler,
	)
}

// Stop gracefully stops the controller, and delete all logical entities for this network if requested
func (oc *BaseSecondaryLayer2NetworkController) Stop() {
	klog.Infof("Stop secondary %s network controller of network %s", oc.TopologyType(), oc.GetNetworkName())
	close(oc.stopChan)
	oc.wg.Wait()

	if oc.policyHandler != nil {
		oc.watchFactory.RemoveMultiNetworkPolicyHandler(oc.policyHandler)
	}
	if oc.podHandler != nil {
		oc.watchFactory.RemovePodHandler(oc.podHandler)
	}
	if oc.namespaceHandler != nil {
		oc.watchFactory.RemoveNamespaceHandler(oc.namespaceHandler)
	}
}

// cleanup cleans up logical entities for the given network, called from net-attach-def routine
// could be called from a dummy Controller (only has CommonNetworkControllerInfo set)
func (oc *BaseSecondaryLayer2NetworkController) cleanup(topotype, netName string) error {
	klog.Infof("Delete OVN logical entities for %s network controller of network %s", topotype, netName)

	// delete layer 2 logical switches
	ops, err := libovsdbops.DeleteLogicalSwitchesWithPredicateOps(oc.nbClient, nil,
		func(item *nbdb.LogicalSwitch) bool {
			return item.ExternalIDs[types.NetworkExternalID] == netName
		})
	if err != nil {
		return fmt.Errorf("failed to get ops for deleting switches of network %s: %v", netName, err)
	}

	ops, err = cleanupPolicyLogicalEntities(oc.nbClient, ops, netName)
	if err != nil {
		return err
	}

	_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
	if err != nil {
		return fmt.Errorf("failed to deleting switches of network %s: %v", netName, err)
	}

	if config.OVNKubernetesFeature.EnableInterconnect {
		if err = oc.zoneICHandler.Cleanup(); err != nil {
			return fmt.Errorf("failed to delete interconnect transit switch of network %s: %v", netName, err)
		}
	}

	return nil
}

func (oc *BaseSecondaryLayer2NetworkController) Run() error {
	klog.Infof("Starting all the Watchers for network %s ...", oc.GetNetworkName())
	start := time.Now()

	// WatchNamespaces() should be started first because it has no other
	// dependencies, and WatchNodes() depends on it
	if err := oc.WatchNamespaces(); err != nil {
		return err
	}

	if err := oc.WatchPods(); err != nil {
		return err
	}

	// WatchMultiNetworkPolicy depends on WatchPods and WatchNamespaces
	if err := oc.WatchMultiNetworkPolicy(); err != nil {
		return err
	}

	klog.Infof("Completing all the Watchers for network %s took %v", oc.GetNetworkName(), time.Since(start))

	// controller is fully running and resource handlers have synced, update Topology version in OVN
	if err := oc.updateL2TopologyVersion(); err != nil {
		return fmt.Errorf("failed to update topology version for network %s: %v", oc.GetNetworkName(), err)
	}

	return nil
}

func (oc *BaseSecondaryLayer2NetworkController) InitializeLogicalSwitch(switchName string, clusterSubnets []config.CIDRNetworkEntry,
	excludeSubnets []*net.IPNet) (*nbdb.LogicalSwitch, error) {
	logicalSwitch := nbdb.LogicalSwitch{
		Name:        switchName,
		ExternalIDs: map[string]string{},
	}
	logicalSwitch.ExternalIDs[types.NetworkExternalID] = oc.GetNetworkName()
	logicalSwitch.ExternalIDs[types.TopologyExternalID] = oc.TopologyType()
	logicalSwitch.ExternalIDs[types.TopologyVersionExternalID] = strconv.Itoa(oc.topologyVersion)

	hostSubnets := make([]*net.IPNet, 0, len(clusterSubnets))
	for _, clusterSubnet := range clusterSubnets {
		subnet := clusterSubnet.CIDR
		hostSubnets = append(hostSubnets, subnet)
		if utilnet.IsIPv6CIDR(subnet) {
			logicalSwitch.OtherConfig = map[string]string{"ipv6_prefix": subnet.IP.String()}
		} else {
			logicalSwitch.OtherConfig = map[string]string{"subnet": subnet.String()}
		}
	}

	err := libovsdbops.CreateOrUpdateLogicalSwitch(oc.nbClient, &logicalSwitch, &logicalSwitch.OtherConfig, &logicalSwitch.ExternalIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to create logical switch %+v: %v", logicalSwitch, err)
	}

	if err = oc.lsManager.AddSwitch(switchName, logicalSwitch.UUID, hostSubnets); err != nil {
		return nil, err
	}

	// FIXME: allocate IP ranges when https://github.com/ovn-org/ovn-kubernetes/issues/3369 is fixed
	for _, excludeSubnet := range excludeSubnets {
		for excludeIP := excludeSubnet.IP; excludeSubnet.Contains(excludeIP); excludeIP = iputils.NextIP(excludeIP) {
			var ipMask net.IPMask
			if excludeIP.To4() != nil {
				ipMask = net.CIDRMask(32, 32)
			} else {
				ipMask = net.CIDRMask(128, 128)
			}
			_ = oc.lsManager.AllocateIPs(switchName, []*net.IPNet{{IP: excludeIP, Mask: ipMask}})
		}
	}

	return &logicalSwitch, nil
}

func (oc *BaseSecondaryLayer2NetworkController) addUpdateLocalNodeEvent(node *kapi.Node, nSyncs *nodeSyncs) error {
	var errs []error
	var err error

	_, _ = oc.localZoneNodes.LoadOrStore(node.Name, true)

	klog.Infof("Adding or Updating Node %q for network %s", node.Name, oc.GetNetworkName())
	if nSyncs.syncNode {
		if err = oc.addNode(node); err != nil {
			oc.addNodeFailed.Store(node.Name, true)
			oc.syncZoneICFailed.Store(node.Name, true)
			err = fmt.Errorf("nodeAdd: error adding node %q for network %s: %w", node.Name, oc.GetNetworkName(), err)
			oc.recordNodeErrorEvent(node, err)
			return err
		}
		oc.addNodeFailed.Delete(node.Name)
	}

	// ensure pods that already exist on this node have their logical ports created
	if nSyncs.syncNode { // do this only if it is a new node add
		errors := oc.addAllPodsOnNode(node.Name)
		errs = append(errs, errors...)
	}

	if nSyncs.syncZoneIC && config.OVNKubernetesFeature.EnableInterconnect {
		if err := oc.zoneICHandler.AddLocalZoneNode(node); err != nil {
			errs = append(errs, err)
			oc.syncZoneICFailed.Store(node.Name, true)
		} else {
			oc.syncZoneICFailed.Delete(node.Name)
		}
	}

	err = kerrors.NewAggregate(errs)
	if err != nil {
		oc.recordNodeErrorEvent(node, err)
	}
	return err
}

func (oc *BaseSecondaryLayer2NetworkController) addUpdateRemoteNodeEvent(node *kapi.Node, syncZoneIc bool) error {
	_, present := oc.localZoneNodes.Load(node.Name)

	if present {
		if err := oc.deleteNodeEvent(node); err != nil {
			return err
		}
	}

	var err error
	if syncZoneIc && config.OVNKubernetesFeature.EnableInterconnect {
		if err = oc.zoneICHandler.AddRemoteZoneNode(node); err != nil {
			err = fmt.Errorf("failed to add the remote zone node [%s] to the zone interconnect handler, err : %v", node.Name, err)
			oc.syncZoneICFailed.Store(node.Name, true)
		} else {
			oc.syncZoneICFailed.Delete(node.Name)
		}
	}
	return err
}

func (oc *BaseSecondaryLayer2NetworkController) isPodScheduledinLocalZone(pod *kapi.Pod) bool {
	if !util.PodScheduled(pod) {
		return false
	}

	_, isLocalZoneNode := oc.localZoneNodes.Load(pod.Spec.NodeName)
	return isLocalZoneNode
}

func (oc *BaseSecondaryLayer2NetworkController) addNode(node *kapi.Node) error {
	// Node subnet for the secondary layer3 network is allocated by cluster manager.
	// Make sure that the node is allocated with the subnet before proceeding
	// to create OVN Northbound resources.
	hostSubnets, err := util.ParseNodeHostSubnetAnnotation(node, oc.GetNetworkName())
	if err != nil || len(hostSubnets) < 1 {
		return fmt.Errorf("subnet annotation in the node %q for the layer3 secondary network %s is missing : %w", node.Name, oc.GetNetworkName(), err)
	}

	// Add the switch to the logical switch cache
	return oc.lsManager.AddSwitch(node.Name, "", hostSubnets)
}

func (oc *BaseSecondaryLayer2NetworkController) deleteNodeEvent(node *kapi.Node) error {
	klog.V(5).Infof("Deleting Node %q for network %s. Removing the node from "+
		"various caches", node.Name, oc.GetNetworkName())

	oc.localZoneNodes.Delete(node.Name)

	oc.lsManager.DeleteSwitch(node.Name)
	oc.addNodeFailed.Delete(node.Name)
	if config.OVNKubernetesFeature.EnableInterconnect {
		if err := oc.zoneICHandler.DeleteNode(node); err != nil {
			return err
		}
		oc.syncZoneICFailed.Delete(node.Name)
	}

	return nil
}

// We only deal with cleaning up nodes that shouldn't exist here, since
// watchNodes() will be called for all existing nodes at startup anyway.
func (oc *BaseSecondaryLayer2NetworkController) syncNodes(nodes []interface{}) error {
	for _, tmp := range nodes {
		node, ok := tmp.(*kapi.Node)
		if !ok {
			return fmt.Errorf("spurious object in syncNodes: %v", tmp)
		}

		// Add the node to the foundNodes only if it belongs to the local zone.
		if oc.isLocalZoneNode(node) {
			oc.localZoneNodes.Store(node.Name, true)
		}
	}

	if config.OVNKubernetesFeature.EnableInterconnect {
		if err := oc.zoneICHandler.SyncNodes(nodes); err != nil {
			return fmt.Errorf("zoneICHandler failed to sync nodes: error: %w", err)
		}
	}

	return nil
}

// ensurePodForSecondaryNetwork tries to set up secondary network for a pod. It returns nil on success and error
// on failure; failure indicates the pod set up should be retried later.
func (oc *BaseSecondaryLayer2NetworkController) ensureRemotePod(pod *kapi.Pod) error {

	// Try unscheduled pods later
	if !util.PodScheduled(pod) {
		return nil
	}

	if util.PodWantsHostNetwork(pod) {
		return nil
	}

	// If a node does not have an assigned hostsubnet don't wait for the logical switch to appear
	/*
		switchName, err := oc.getExpectedSwitchName(pod)
		if err != nil {
			return err
		}
	*/
	subnetName, err := oc.getExpectedSubnetName(pod)
	if err != nil {
		return err
	}
	on, networkMap, err := util.GetPodNADToNetworkMapping(pod, oc.NetInfo)
	if err != nil {
		// configuration error, no need to retry, do not return error
		klog.Errorf("Error getting network-attachment for pod %s/%s network %s: %v",
			pod.Namespace, pod.Name, oc.GetNetworkName(), err)
		return nil
	}

	if !on {
		// the pod is not attached to this specific network
		klog.V(5).Infof("Pod %s/%s is not attached on this network controller %s",
			pod.Namespace, pod.Name, oc.GetNetworkName())
		return nil
	}

	if oc.doesNetworkRequireIPAM() && oc.lsManager.IsNonHostSubnetSwitch(subnetName) {
		klog.V(5).Infof(
			"Pod %s/%s requires IPAM but does not have an assigned IP address", pod.Namespace, pod.Name)
		return nil
	}

	var errs []error
	for nadName := range networkMap {
		err := oc.zoneICHandler.AddRemoteZonePod(pod, nadName)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to add remotelogical  port of Pod %s/%s for NAD %s", pod.Namespace, pod.Name, nadName))
		}
	}
	if len(errs) != 0 {
		return kerrors.NewAggregate(errs)
	}
	return nil
}
