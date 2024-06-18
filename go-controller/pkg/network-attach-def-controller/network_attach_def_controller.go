package networkAttachDefController

import (
	"context"
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	nettypes "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	nadinformer "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/informers/externalversions/k8s.cni.cncf.io/v1"
	nadlisters "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/listers/k8s.cni.cncf.io/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/controller"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/syncmap"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

var ErrNetworkControllerTopologyNotManaged = errors.New("no cluster network controller to manage topology")

type BaseNetworkController interface {
	Start(ctx context.Context) error
	Stop()
	GetNetworkName() string
	TopologyType() string
}

type NetworkController interface {
	BaseNetworkController
	CompareNetInfo(util.BasicNetInfo) bool
	AddNAD(nadName string)
	DeleteNAD(nadName string)
	HasNAD(nadName string) bool
	// Cleanup cleans up the NetworkController-owned resources, it could be called to clean up network controllers that are deleted when
	// ovn-k8s is down; so it's receiver could be a dummy network controller, it just needs to know its network name.
	Cleanup() error
}

// NetworkControllerManager manages all network controllers
type NetworkControllerManager interface {
	NewNetworkController(netInfo util.NetInfo) (NetworkController, error)
	CleanupDeletedNetworks(allControllers []NetworkController) error
}

type networkNADInfo struct {
	nadNames  sets.Set[string]
	nc        NetworkController
	isStarted bool
	isDeleted bool
}

type NetAttachDefinitionController struct {
	name               string
	recorder           record.EventRecorder
	ncm                NetworkControllerManager
	netAttachDefLister nadlisters.NetworkAttachmentDefinitionLister
	controller         controller.Controller

	// key is nadName, value is BasicNetInfo
	perNADNetInfo *syncmap.SyncMap[util.BasicNetInfo]
	// controller for all networks, key is netName of net-attach-def, value is networkNADInfo
	// this map is updated either at the very beginning of ovnkube controller when initializing the
	// default controller or when net-attach-def is added/deleted. All these are serialized by syncmap lock
	perNetworkNADInfo *syncmap.SyncMap[*networkNADInfo]
}

func NewNetAttachDefinitionController(name string, ncm NetworkControllerManager, nadInformer nadinformer.NetworkAttachmentDefinitionInformer, recorder record.EventRecorder) (*NetAttachDefinitionController, error) {
	nadController := &NetAttachDefinitionController{
		name:               name,
		recorder:           recorder,
		ncm:                ncm,
		netAttachDefLister: nadInformer.Lister(),
		perNADNetInfo:      syncmap.NewSyncMap[util.BasicNetInfo](),
		perNetworkNADInfo:  syncmap.NewSyncMap[*networkNADInfo](),
	}
	config := &controller.Config[nettypes.NetworkAttachmentDefinition]{
		RateLimiter: workqueue.DefaultControllerRateLimiter(),
		Informer:    nadInformer.Informer(),
		Lister:      nadController.netAttachDefLister.List,
		Reconcile:   nadController.sync,
		Threadiness: 2,
	}

	nadController.controller = controller.NewController(
		fmt.Sprintf("NAD controller %s", nadController.name),
		config,
	)

	return nadController, nil
}

func (nadController *NetAttachDefinitionController) Start() error {
	klog.Infof("Starting %s NAD controller", nadController.name)
	return controller.StartControllersWithInitialSync(
		nadController.SyncNetworkControllers,
		nadController.controller,
	)
}

func (nadController *NetAttachDefinitionController) Stop() {
	klog.Infof("Shutting down %s NAD controller", nadController.name)
	controller.StopControllers(nadController.controller)

	// stop each network controller
	started := func(nni *networkNADInfo) bool { return nni.isStarted }
	for _, oc := range nadController.getNetworkControllers(started) {
		oc.Stop()
	}
}

func (nadController *NetAttachDefinitionController) SyncNetworkControllers() (err error) {
	startTime := time.Now()
	klog.V(4).Infof("Starting repairing loop for %s", nadController.name)
	defer func() {
		klog.V(4).Infof("Finished repairing loop for %s: %v err: %v", nadController.name,
			time.Since(startTime), err)
	}()

	existingNADs, err := nadController.netAttachDefLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("failed to get list of all net-attach-def")
	}

	// Need to walk through all the NADs and create all network controllers and update their list of NADs.
	// The controller can only be started after all known NADs are added so as to avoid to the extent possible
	// the errors and retries that would result if the controller attempted to process pods attached with NADs
	// we wouldn't otherwise know about yet
	for _, nad := range existingNADs {
		err = nadController.AddNetAttachDef(nadController.ncm, nad, false)
		// Ignore the error if there is no network controller to manager a topology
		if err != nil && !errors.Is(err, ErrNetworkControllerTopologyNotManaged) {
			return err
		}
	}

	all := func(nn *networkNADInfo) bool { return true }
	return nadController.ncm.CleanupDeletedNetworks(nadController.getNetworkControllers(all))
}

func (nadController *NetAttachDefinitionController) sync(key string) error {
	startTime := time.Now()
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	klog.V(5).Infof("%s: Sync net-attach-def %s/%s", nadController.name, namespace, name)
	defer func() {
		klog.V(4).Infof("%s: Finished syncing net-attach-def %s/%s: %v", nadController.name, namespace, name, time.Since(startTime))
	}()

	nad, err := nadController.netAttachDefLister.NetworkAttachmentDefinitions(namespace).Get(name)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	if nad == nil {
		return nadController.DeleteNetAttachDef(key)
	}

	nInfo, err := util.ParseNADInfo(nad)
	if err != nil {
		return err
	}

	networkName := nInfo.GetNetworkName()
	var nadDeleteInProgress bool
	nadController.perNetworkNADInfo.DoWithLock(networkName, func(string) error {
		nni, _ := nadController.perNetworkNADInfo.Load(networkName)
		nadDeleteInProgress = nni != nil && nni.isDeleted && nni.nadNames.Has(key)
		return nil
	})
	if nadDeleteInProgress {
		err := nadController.DeleteNetAttachDef(key)
		if err != nil {
			return err
		}
	}

	return nadController.AddNetAttachDef(nadController.ncm, nad, true)
}

// getNetworkControllers returns a snapshot of all managed NAD associated
// network controllers that comply with the provided predicate. Caller needs to
// note that there are no guarantees the return results reflect the real time
// condition. There maybe more controllers being added, and returned controllers
// may be deleted
func (nadController *NetAttachDefinitionController) getNetworkControllers(p func(*networkNADInfo) bool) []NetworkController {
	allNetworkNames := nadController.perNetworkNADInfo.GetKeys()
	allNetworkControllers := make([]NetworkController, 0, len(allNetworkNames))
	for _, netName := range allNetworkNames {
		nadController.perNetworkNADInfo.LockKey(netName)
		nni, ok := nadController.perNetworkNADInfo.Load(netName)
		if ok && p(nni) {
			allNetworkControllers = append(allNetworkControllers, nni.nc)
		}
		nadController.perNetworkNADInfo.UnlockKey(netName)
	}
	return allNetworkControllers
}

// AddNetAttachDef adds the given nad to the associated controller. It creates the controller if this
// is the first NAD of the network.
// Non-retriable errors (configuration error etc.) are just logged, and the function immediately returns nil.
func (nadController *NetAttachDefinitionController) AddNetAttachDef(ncm NetworkControllerManager,
	netattachdef *nettypes.NetworkAttachmentDefinition, doStart bool) error {
	var nInfo util.NetInfo
	var err, invalidNADErr error
	var netName string

	netAttachDefName := util.GetNADName(netattachdef.Namespace, netattachdef.Name)
	klog.Infof("%s: Add net-attach-def %s", nadController.name, netAttachDefName)

	nInfo, invalidNADErr = util.ParseNADInfo(netattachdef)
	if invalidNADErr == nil {
		netName = nInfo.GetNetworkName()
		if netName == types.DefaultNetworkName {
			invalidNADErr = fmt.Errorf("NAD for default network, skip it")
		}
	}

	return nadController.perNADNetInfo.DoWithLock(netAttachDefName, func(nadName string) error {
		nadNci, loaded := nadController.perNADNetInfo.LoadOrStore(nadName, nInfo)
		if !loaded {
			// first time to process this nad
			if invalidNADErr != nil {
				// invalid nad, nothing to do
				klog.Warningf("%s: net-attach-def %s is first seen and is invalid: %v", nadController.name, nadName, invalidNADErr)
				nadController.perNADNetInfo.Delete(nadName)
				return nil
			}
			klog.V(5).Infof("%s: net-attach-def %s network %s first seen", nadController.name, nadName, netName)
			err = nadController.addNADToController(ncm, nadName, nInfo, doStart)
			if err != nil {
				klog.Errorf("%s: Failed to add net-attach-def %s to network %s: %v", nadController.name, nadName, netName, err)
				nadController.perNADNetInfo.Delete(nadName)
				return err
			}
		} else {
			klog.V(5).Infof("%s: net-attach-def %s network %s already exists", nadController.name, nadName, netName)
			nadUpdated := false
			if invalidNADErr != nil {
				nadUpdated = true
			} else if !nadNci.CompareNetInfo(nInfo) {
				// netconf spec changed
				klog.V(5).Infof("%s: net-attach-def %s spec has changed", nadController.name, nadName)
				nadUpdated = true
			}

			if !nadUpdated {
				// nothing changed, may still need to start the controller
				if !doStart {
					return nil
				}
				err = nadController.addNADToController(ncm, nadName, nInfo, doStart)
				if err != nil {
					klog.Errorf("%s: Failed to add net-attach-def %s to network %s: %v", nadController.name, nadName, netName, err)
					return err
				}
				return nil
			}
			if nadUpdated {
				klog.V(5).Infof("%s: net-attach-def %s network %s updated", nadController.name, nadName, netName)
				// delete the NAD from the old network first
				oldNetName := nadNci.GetNetworkName()
				err := nadController.deleteNADFromController(oldNetName, nadName)
				if err != nil {
					klog.Errorf("%s: Failed to delete net-attach-def %s from network %s: %v", nadController.name, nadName, oldNetName, err)
					return err
				}
				nadController.perNADNetInfo.Delete(nadName)
			}
			if invalidNADErr != nil {
				klog.Warningf("%s: net-attach-def %s is invalid: %v", nadController.name, nadName, invalidNADErr)
				return nil
			}
			klog.V(5).Infof("%s: Add updated net-attach-def %s to network %s", nadController.name, nadName, netName)
			nadController.perNADNetInfo.LoadOrStore(nadName, nInfo)
			err = nadController.addNADToController(ncm, nadName, nInfo, doStart)
			if err != nil {
				klog.Errorf("%s: Failed to add net-attach-def %s to network %s: %v", nadController.name, nadName, netName, err)
				nadController.perNADNetInfo.Delete(nadName)
				return err
			}
			return nil
		}
		return nil
	})
}

// DeleteNetAttachDef deletes the given NAD from the associated controller. It delete the controller if this
// is the last NAD of the network
func (nadController *NetAttachDefinitionController) DeleteNetAttachDef(netAttachDefName string) error {
	klog.Infof("%s: Delete net-attach-def %s", nadController.name, netAttachDefName)
	return nadController.perNADNetInfo.DoWithLock(netAttachDefName, func(nadName string) error {
		existingNadNetConfInfo, found := nadController.perNADNetInfo.Load(nadName)
		if !found {
			klog.V(5).Infof("%s: net-attach-def %s not found for removal", nadController.name, nadName)
			return nil
		}
		netName := existingNadNetConfInfo.GetNetworkName()
		err := nadController.deleteNADFromController(netName, nadName)
		if err != nil {
			klog.Errorf("%s: Failed to delete net-attach-def %s from network %s: %v", nadController.name, nadName, netName, err)
			return err
		}
		nadController.perNADNetInfo.Delete(nadName)
		return nil
	})
}

func (nadController *NetAttachDefinitionController) addNADToController(ncm NetworkControllerManager, nadName string,
	nInfo util.NetInfo, doStart bool) (err error) {
	var oc NetworkController
	var nadExists, isStarted bool

	netName := nInfo.GetNetworkName()
	klog.V(5).Infof("%s: Add net-attach-def %s to network %s", nadController.name, nadName, netName)
	return nadController.perNetworkNADInfo.DoWithLock(netName, func(networkName string) error {
		nni, loaded := nadController.perNetworkNADInfo.LoadOrStore(networkName, &networkNADInfo{
			nadNames:  sets.Set[string]{},
			nc:        nil,
			isStarted: false,
		})
		if !loaded {
			defer func() {
				if err != nil {
					nadController.perNetworkNADInfo.Delete(networkName)
				}
			}()
			// first NAD for this network, create controller
			klog.V(5).Infof("%s: First net-attach-def %s of network %s added, create network controller", nadController.name, nadName, networkName)
			oc, err = ncm.NewNetworkController(nInfo)
			if err != nil {
				return err
			}
			nni.nc = oc
		} else {
			if nni.isDeleted {
				return fmt.Errorf("%s: can't add net-attach-def %s to network %s, network delete in progress", nadController.name, nadName, networkName)
			}

			klog.V(5).Infof("%s: net-attach-def %s added to existing network %s", nadController.name, nadName, networkName)
			// controller of this network already exists
			oc = nni.nc
			isStarted = nni.isStarted
			nadExists = nni.nadNames.Has(nadName)

			if !oc.CompareNetInfo(nInfo) {
				if nadExists {
					// this should not happen, continue to start the existing controller if requested
					return fmt.Errorf("%s: net-attach-def %s netconf spec changed, should not happen", nadController.name, networkName)
				} else {
					return fmt.Errorf("%s: NAD %s does not share the same CNI config with network %s",
						nadController.name, nadName, networkName)
				}
			}
		}
		if !nadExists {
			nni.nadNames.Insert(nadName)
			nni.nc.AddNAD(nadName)
			defer func() {
				if err != nil {
					nni.nadNames.Delete(nadName)
					nni.nc.DeleteNAD(nadName)
				}
			}()
		}

		if !doStart || isStarted {
			return nil
		}

		klog.V(5).Infof("%s: Start network controller for network %s", nadController.name, networkName)
		// start the controller if requested
		err = oc.Start(context.TODO())
		if err == nil {
			nni.isStarted = true
			return nil
		}
		return fmt.Errorf("%s: network controller for network %s failed to be started: %v", nadController.name, networkName, err)
	})
}

func (nadController *NetAttachDefinitionController) deleteNADFromController(netName, nadName string) error {
	klog.V(5).Infof("%s: Delete net-attach-def %s from network %s", nadController.name, nadName, netName)
	return nadController.perNetworkNADInfo.DoWithLock(netName, func(networkName string) error {
		nni, found := nadController.perNetworkNADInfo.Load(networkName)
		if !found {
			klog.V(5).Infof("%s: Network controller for network %s not found", nadController.name, networkName)
			return nil
		}
		nadExists := nni.nadNames.Has(nadName)
		if !nadExists {
			klog.V(5).Infof("%s: Unable to remove NAD %s, does not exist on network %s", nadController.name, nadName, networkName)
			return nil
		}

		oc := nni.nc
		nni.nadNames.Delete(nadName)
		if nni.nadNames.Len() == 0 {
			klog.V(5).Infof("%s: The last NAD: %s of network %s has been deleted, stopping network controller", nadController.name, nadName, networkName)
			if nni.isStarted {
				oc.Stop()
			}
			nni.isStarted = false
			// once a controller has been stopped, we don't want to reuse it so
			// flag it
			nni.isDeleted = true
			err := oc.Cleanup()
			if err != nil {
				nni.nadNames.Insert(nadName)
				return fmt.Errorf("%s: failed to stop network controller for network %s: %v", nadController.name, networkName, err)
			}
			nadController.perNetworkNADInfo.Delete(networkName)
		}
		nni.nc.DeleteNAD(nadName)
		klog.V(5).Infof("%s: Delete NAD %s from controller of network %s", nadController.name, nadName, networkName)
		return nil
	})
}
