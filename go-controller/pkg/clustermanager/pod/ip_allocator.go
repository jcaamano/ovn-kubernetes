package pod

import (
	"fmt"
	"net"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	nettypes "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/subnetipallocator"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

type PodIPAllocator struct {
	netInfo util.NetInfo

	// TODO: refactor LogicalSwitchManager to be just a subnet manager
	allocator *subnetipallocator.SubnetIPAllocator

	releasedPods      map[string]sets.Set[string]
	releasedPodsMutex sync.Mutex

	podLister listers.PodLister
	kube      kube.Interface
}

func NewPodIPAllocator(netInfo util.NetInfo, podLister listers.PodLister, kube kube.Interface) *PodIPAllocator {
	podIPAllocator := &PodIPAllocator{
		netInfo:           netInfo,
		releasedPods:      map[string]sets.Set[string]{},
		releasedPodsMutex: sync.Mutex{},
		podLister:         podLister,
		kube:              kube,
	}

	if util.DoesNetworkRequireIPAM(netInfo) {
		podIPAllocator.allocator = subnetipallocator.NewSubnetIPAllocator()
	}

	return podIPAllocator
}

func (a *PodIPAllocator) InitRanges() error {
	subnets := a.netInfo.Subnets()
	ipNets := make([]*net.IPNet, 0, len(subnets))
	for _, subnet := range subnets {
		ipNets = append(ipNets, subnet.CIDR)
	}
	return a.allocator.AddSubnet(a.netInfo.GetNetworkName(), ipNets, a.netInfo.ExcludeSubnets()...)
}

func (a *PodIPAllocator) Reconcile(old, new *corev1.Pod) error {
	release := true
	return a.reconcile(old, new, release)
}

func (a *PodIPAllocator) Sync(objs []interface{}) error {
	// on sync there is no need to release and specifically we don't want to
	// release IPs of completed pods that might be being used by other pods
	no_release := false
	for _, obj := range objs {
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			klog.Errorf("Could not cast %T object to *corev1.Pod", obj)
			continue
		}
		err := a.reconcile(nil, pod, no_release)
		if err != nil {
			klog.Errorf("Failed to sync pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
	}

	return nil
}

func (a *PodIPAllocator) reconcile(old, new *corev1.Pod, release bool) error {
	var pod *corev1.Pod
	if old != nil {
		pod = old
	}
	if new != nil {
		pod = new
	}

	podScheduled := util.PodScheduled(pod)
	podWantsHostNetwork := util.PodWantsHostNetwork(pod)

	// nothing to do for a unscheduled or host network pods
	if !podScheduled || podWantsHostNetwork {
		return nil
	}

	onNetwork, networkMap, err := util.GetPodNADToNetworkMapping(pod, a.netInfo)
	if err != nil {
		return fmt.Errorf("failed to get NAD to network mapping: %w", err)
	}

	// nothing to do if not on this network
	if !onNetwork {
		return nil
	}

	for nadName, network := range networkMap {
		err = a.reconcileForNAD(old, new, nadName, network, release)
		if err != nil {
			return err
		}
	}

	return nil
}

func (a *PodIPAllocator) reconcileForNAD(old, new *corev1.Pod, nad string, network *nettypes.NetworkSelectionElement, release bool) error {
	var pod *corev1.Pod
	if old != nil {
		pod = old
	}
	if new != nil {
		pod = new
	}
	podDeleted := new == nil
	name := pod.Name
	namespace := pod.Namespace
	uid := string(pod.UID)
	podCompleted := util.PodCompleted(pod)
	podReleased := a.isPodReleased(nad, uid)

	defer func() {
		if podDeleted {
			a.deleteReleasedPod(nad, uid)
		} else if podCompleted {
			a.addReleasedPod(nad, uid)
		}
	}()

	podAnnotation, _ := util.UnmarshalPodAnnotation(pod.Annotations, nad)
	if podAnnotation == nil {
		podAnnotation = &util.PodAnnotation{}
	}

	if (podCompleted || podDeleted) && !podReleased {
		// release is disabled
		if !release {
			return nil
		}

		err := a.allocator.ReleaseIPs(a.netInfo.GetNetworkName(), podAnnotation.IPs)
		if err != nil {
			return fmt.Errorf("failed to release ips %s for pod %s/%s and nad %s: %w",
				util.JoinIPNetIPs(podAnnotation.IPs, " "),
				namespace,
				name,
				nad,
				err,
			)
		}
		return nil
	}

	updatePodAnnotation := func(p *corev1.Pod, annotation *util.PodAnnotation, nad string) error {
		return util.UpdatePodAnnotationWithRetry(a.podLister, a.kube, p, annotation, nad)
	}

	// annotator handles release in case or error
	annotator := util.PodAnnotationAllocator{
		NetInfo:             a.netInfo,
		IPAllocator:         a.allocator.WithSubnet(a.netInfo.GetNetworkName()),
		PodAnnotationUpdate: updatePodAnnotation,
	}

	reallocateOnError := false
	_, _, err := annotator.AllocatePodAnnotation(pod, podAnnotation, network, reallocateOnError)
	return err
}

func (a *PodIPAllocator) addReleasedPod(nad, uid string) {
	a.releasedPodsMutex.Lock()
	defer a.releasedPodsMutex.Unlock()
	releasedPods := a.releasedPods[nad]
	if releasedPods == nil {
		a.releasedPods[nad] = sets.New(uid)
		return
	}
	releasedPods.Insert(uid)
}

func (a *PodIPAllocator) deleteReleasedPod(nad, uid string) {
	a.releasedPodsMutex.Lock()
	defer a.releasedPodsMutex.Unlock()
	releasedPods := a.releasedPods[nad]
	if releasedPods != nil {
		releasedPods.Delete(uid)
		if releasedPods.Len() == 0 {
			delete(a.releasedPods, nad)
		}
	}
}

func (a *PodIPAllocator) isPodReleased(nad, uid string) bool {
	a.releasedPodsMutex.Lock()
	defer a.releasedPodsMutex.Unlock()
	releasedPods := a.releasedPods[nad]
	if releasedPods != nil {
		return releasedPods.Has(uid)
	}
	return false
}
