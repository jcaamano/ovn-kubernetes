package networkAttachDefController

import (
	"context"
	"fmt"
	"sync"
	"time"

	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/controller"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

type networkManager interface {
	EnsureNetwork(util.NetInfo)
	DeleteNetwork(string)
	Start() error
	Stop()
}

func newNetworkManager(name string, ncm NetworkControllerManager) networkManager {
	nc := &networkManagerImpl{
		name:               name,
		ncm:                ncm,
		networks:           map[string]util.NetInfo{},
		networkControllers: map[string]*networkControllerState{},
	}
	// this controller does not feed from an informer, networks are manually
	// added to the queue for processing
	config := &controller.Config[string]{
		RateLimiter: workqueue.DefaultControllerRateLimiter(),
		Reconcile:   nc.sync,
		Threadiness: 1,
	}
	nc.controller = controller.NewController(
		fmt.Sprintf("Network manager %s", nc.name),
		config,
	)
	return nc
}

type networkControllerState struct {
	controller         NetworkController
	stoppedAndDeleting bool
}

type networkManagerImpl struct {
	sync.Mutex
	name               string
	controller         controller.Controller
	ncm                NetworkControllerManager
	networks           map[string]util.NetInfo
	networkControllers map[string]*networkControllerState
}

func (nm *networkManagerImpl) Start() error {
	return controller.StartControllersWithInitialSync(nm.syncAll, nm.controller)
}

func (nm *networkManagerImpl) Stop() {
	controller.StopControllers(nm.controller)

	for _, networkControllerState := range nm.networkControllers {
		networkControllerState.controller.Stop()
	}
}

func (nm *networkManagerImpl) EnsureNetwork(network util.NetInfo) {
	nm.Lock()
	defer nm.Unlock()
	nm.networks[network.GetNetworkName()] = network
	nm.controller.Reconcile(network.GetNetworkName())
}

func (nm *networkManagerImpl) DeleteNetwork(network string) {
	nm.Lock()
	defer nm.Unlock()
	delete(nm.networks, network)
	nm.controller.Reconcile(network)
}

func (nm *networkManagerImpl) sync(network string) error {
	nm.Lock()
	defer nm.Unlock()

	startTime := time.Now()
	klog.V(5).Infof("Network manager %s: sync network %s", nm.name, network)
	defer func() {
		klog.V(4).Infof("Network manager %s: finished syncing network %s, took %v", nm.name, network, time.Since(startTime))
	}()

	want := nm.networks[network]
	have := nm.networkControllers[network]

	// we will dispose of the old network if deletion is in progress or if
	// configuration changed
	dispose := have != nil && (have.stoppedAndDeleting || !have.controller.CompareNetInfo(want))

	if dispose {
		if !have.stoppedAndDeleting {
			have.controller.Stop()
		}
		have.stoppedAndDeleting = true
		err := have.controller.Cleanup()
		if err != nil {
			return fmt.Errorf("network manager %s: failed to cleanup network %s: %w", nm.name, network, err)
		}
		delete(nm.networkControllers, network)
	}

	// no network needed so nothing to do
	if want == nil {
		return nil
	}

	// this might just be an update of the network NADs
	if !dispose {
		have.controller.SetNADs(want.GetNADs()...)
		return nil
	}

	// setup & start the new network controller
	nc, err := nm.ncm.NewNetworkController(want)
	if err != nil {
		return fmt.Errorf("network manager %s: failed to create network %s: %w", nm.name, network, err)
	}

	err = nc.Start(context.Background())
	if err != nil {
		return fmt.Errorf("network manager %s: failed to start network %s: %w", nm.name, network, err)
	}
	nm.networkControllers[network] = &networkControllerState{controller: nc}

	return nil
}

func (nm *networkManagerImpl) syncAll() error {
	networkControllers := make([]NetworkController, 0, len(nm.networkControllers))
	for _, networkControllerState := range nm.networkControllers {
		networkControllers = append(networkControllers, networkControllerState.controller)
	}
	return nm.ncm.CleanupDeletedNetworks(networkControllers)
}
