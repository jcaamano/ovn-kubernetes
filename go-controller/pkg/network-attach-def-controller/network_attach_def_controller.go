package networkAttachDefController

import (
	"context"
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	nettypes "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	nadinformer "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/informers/externalversions/k8s.cni.cncf.io/v1"
	nadlisters "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/listers/k8s.cni.cncf.io/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/controller"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

var ErrNetworkControllerTopologyNotManaged = errors.New("no cluster network controller to manage topology")

type BaseNetworkController interface {
	Start(ctx context.Context) error
	Stop()
}

type NetworkController interface {
	BaseNetworkController
	util.NetInfo
	// Cleanup cleans up the NetworkController-owned resources, it could be called to clean up network controllers that are deleted when
	// ovn-k8s is down; so it's receiver could be a dummy network controller, it just needs to know its network name.
	Cleanup() error
}

// NetworkControllerManager manages all network controllers
type NetworkControllerManager interface {
	NewNetworkController(netInfo util.NetInfo) (NetworkController, error)
	CleanupDeletedNetworks(allControllers []NetworkController) error
}

type NetAttachDefinitionController struct {
	name               string
	recorder           record.EventRecorder
	netAttachDefLister nadlisters.NetworkAttachmentDefinitionLister
	controller         controller.Controller
	networkManager     networkManager

	networks map[string]util.NetInfo
	nads     map[string]string
}

func NewNetAttachDefinitionController(name string, ncm NetworkControllerManager, nadInformer nadinformer.NetworkAttachmentDefinitionInformer, recorder record.EventRecorder) (*NetAttachDefinitionController, error) {
	nadController := &NetAttachDefinitionController{
		name:               name,
		recorder:           recorder,
		netAttachDefLister: nadInformer.Lister(),
		networkManager:     newNetworkManager(name, ncm),
	}
	config := &controller.Config[nettypes.NetworkAttachmentDefinition]{
		RateLimiter: workqueue.DefaultControllerRateLimiter(),
		Informer:    nadInformer.Informer(),
		Lister:      nadController.netAttachDefLister.List,
		Reconcile:   nadController.sync,
		Threadiness: 1,
	}
	nadController.controller = controller.NewController(
		fmt.Sprintf("NAD controller %s", nadController.name),
		config,
	)

	return nadController, nil
}

func (nadController *NetAttachDefinitionController) Start() error {
	err := controller.StartControllersWithInitialSync(
		nadController.syncAll,
		nadController.controller,
	)
	if err != nil {
		return err
	}

	err = nadController.networkManager.Start()
	if err != nil {
		return err
	}

	klog.Infof("NAD controller %s: started", nadController.name)
	return nil
}

func (nadController *NetAttachDefinitionController) Stop() {
	klog.Infof("NAD controller %s: shutting down", nadController.name)
	controller.StopControllers(nadController.controller)
	nadController.networkManager.Stop()
}

func (nadController *NetAttachDefinitionController) syncAll() (err error) {
	existingNADs, err := nadController.netAttachDefLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("NAD controller %s: failed to list NADs: %w", nadController.name, err)
	}

	// Need to walk through all the NADs and create all network controllers and update their list of NADs.
	// The controller can only be started after all known NADs are added so as to avoid to the extent possible
	// the errors and retries that would result if the controller attempted to process pods attached with NADs
	// we wouldn't otherwise know about yet
	for _, nad := range existingNADs {
		key, err := cache.MetaNamespaceKeyFunc(nad)
		if err != nil {
			klog.Errorf("NAD controller %s: failed to sync %v: %v", nadController.name, nad, err)
			continue
		}
		err = nadController.sync(key)
		if err != nil {
			return fmt.Errorf("NAD controller %s: failed to sync %s: %v", nadController.name, key, err)
		}
	}

	return nil
}

func (nadController *NetAttachDefinitionController) sync(key string) error {
	startTime := time.Now()
	klog.V(5).Infof("NAD controller %s: sync NAD %s", nadController.name, key)
	defer func() {
		klog.V(4).Infof("NAD controller %s: finished syncing NAD %s, took %v", nadController.name, key, time.Since(startTime))
	}()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		klog.Errorf("NAD controller %s: failed splitting key %s: %v", nadController.name, key, err)
		return nil
	}

	nad, err := nadController.netAttachDefLister.NetworkAttachmentDefinitions(namespace).Get(name)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	return nadController.syncNAD(key, nad)
}

func (nadController *NetAttachDefinitionController) syncNAD(key string, nad *nettypes.NetworkAttachmentDefinition) error {
	oldNetworkName := nadController.nads[key]
	var networkName string
	var nInfo util.NetInfo
	if nad != nil {
		nInfo, err := util.ParseNADInfo(nad)
		if err != nil {
			klog.Errorf("NAD controller %s: failed parsing NAD %s: %v", nadController.name, key, err)
			return nil
		}
		networkName = nInfo.GetNetworkName()
	}

	// if the NAD refers to a different network than before, remove the NAD
	// reference from the old network and delete the network if it is no longer
	// referenced
	if networkName != oldNetworkName {
		oldNetwork := nadController.networks[oldNetworkName]
		if oldNetwork != nil {
			oldNetwork.DeleteNADs(key)
			if len(oldNetwork.GetNADs()) == 0 {
				nadController.networkManager.DeleteNetwork(oldNetworkName)
				delete(nadController.networks, oldNetworkName)
			} else {
				nadController.networkManager.EnsureNetwork(oldNetwork)
			}
		}
	}

	// the NAD was deleted, nothing else to do
	if networkName == "" {
		return nil
	}

	// if network already exists, validate the config and add the NAD reference,
	// otherwise just add the new network
	network := nadController.networks[networkName]
	if network != nil {
		if network.CompareNetInfo(nInfo) {
			return fmt.Errorf("NAD controller %s: NAD %s CNI config does not match that of network %s", nadController.name, key, networkName)
		}
		network.AddNADs(key)
	} else {
		network = nInfo
		nadController.networks[networkName] = network
	}

	nadController.networkManager.EnsureNetwork(network)
	return nil
}
