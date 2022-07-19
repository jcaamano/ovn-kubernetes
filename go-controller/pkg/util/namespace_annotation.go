package util

import (
	"fmt"
	"net"
	"strings"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	kapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
)

const (
	// Annotation used to enable/disable multicast in the namespace
	NsMulticastAnnotation = "k8s.ovn.org/multicast-enabled"
	// Annotations used by multiple external gateways feature
	RoutingExternalGWsAnnotation    = "k8s.ovn.org/routing-external-gws"
	RoutingNamespaceAnnotation      = "k8s.ovn.org/routing-namespaces"
	RoutingNetworkAnnotation        = "k8s.ovn.org/routing-network"
	BfdAnnotation                   = "k8s.ovn.org/bfd-enabled"
	ExternalGatewayPodIPsAnnotation = "k8s.ovn.org/external-gw-pod-ips"
	// Annotation for enabling ACL logging to controller's log file
	AclLoggingAnnotation = "k8s.ovn.org/acl-logging"
)

func UpdateExternalGatewayPodIPsAnnotation(k kube.Interface, namespace string, exgwIPs []string) error {
	exgwPodAnnotation := strings.Join(exgwIPs, ",")
	nsObjWithName := &kapi.Namespace{
		// NOTE: This should be used only in current context since we know SetAnnotationsOnNamespace only needs Name
		ObjectMeta: metav1.ObjectMeta{
			Name:      namespace,
		},
	}
	err := k.SetAnnotationsOnNamespace(nsObjWithName, map[string]string{ExternalGatewayPodIPsAnnotation: exgwPodAnnotation})
	if err != nil {
		return fmt.Errorf("failed to add annotation %s/%v for namespace %s: %v", ExternalGatewayPodIPsAnnotation, exgwPodAnnotation, namespace, err)
	}
	return nil
}

func ParseRoutingExternalGWAnnotation(annotation string) (sets.String, error) {
	ipTracker := sets.NewString()
	for _, v := range strings.Split(annotation, ",") {
		parsedAnnotation := net.ParseIP(v)
		if parsedAnnotation == nil {
			return nil, fmt.Errorf("could not parse routing external gw annotation value %s", v)
		}
		if ipTracker.Has(parsedAnnotation.String()) {
			klog.Warningf("Duplicate IP detected in routing external gw annotation: %s", annotation)
			continue
		}
		ipTracker.Insert(parsedAnnotation.String())
	}
	return ipTracker, nil
}
