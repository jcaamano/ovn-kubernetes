package networkAttachDefController

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/onsi/gomega"
	"github.com/onsi/gomega/format"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	nettypes "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"

	ovncnitypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

type testNetworkController struct {
	util.NetInfo
	tncm *testNetworkControllerManager
}

func (tnc *testNetworkController) Start(context.Context) error {
	tnc.tncm.Lock()
	defer tnc.tncm.Unlock()
	tnc.tncm.started = append(tnc.tncm.started, testNetworkKey(tnc))
	return nil
}

func (tnc *testNetworkController) Stop() {
	tnc.tncm.Lock()
	defer tnc.tncm.Unlock()
	tnc.tncm.stopped = append(tnc.tncm.stopped, testNetworkKey(tnc))
}

func (tnc *testNetworkController) Cleanup() error {
	tnc.tncm.Lock()
	defer tnc.tncm.Unlock()
	tnc.tncm.cleaned = append(tnc.tncm.cleaned, testNetworkKey(tnc))
	return nil
}

func (tncm *testNetworkController) Reconcile(netInfo util.ReconcilableNetInfo) error {
	tncm.SetNADs(netInfo.GetNADs()...)
	if !tncm.IsSecondary() {
		tncm.SetVRFs(netInfo.GetVRFs())
	}
	return nil
}

// GomegaString is used to avoid printing embedded mutexes which can cause a
// race
func (tnc *testNetworkController) GomegaString() string {
	return format.Object(tnc.NetInfo.GetNetworkName(), 1)
}

func testNetworkKey(nInfo util.NetInfo) string {
	return nInfo.GetNetworkName() + " " + nInfo.TopologyType()
}

type testNetworkControllerManager struct {
	sync.Mutex

	defaultNetwork *testNetworkController
	controllers    map[string]NetworkController

	started []string
	stopped []string
	cleaned []string

	valid []util.BasicNetInfo
}

func (tncm *testNetworkControllerManager) NewNetworkController(netInfo util.NetInfo) (NetworkController, error) {
	tncm.Lock()
	defer tncm.Unlock()
	t := &testNetworkController{
		NetInfo: netInfo,
		tncm:    tncm,
	}
	tncm.controllers[testNetworkKey(netInfo)] = t
	return t, nil
}

func (tncm *testNetworkControllerManager) CleanupDeletedNetworks(validNetworks ...util.BasicNetInfo) error {
	tncm.valid = validNetworks
	return nil
}

func (tncm *testNetworkControllerManager) GetDefaultNetworkController() ReconcilableNetworkController {
	return tncm.defaultNetwork
}

func TestNetAttachDefinitionController(t *testing.T) {
	network_A := &ovncnitypes.NetConf{
		Topology: types.Layer2Topology,
		NetConf: cnitypes.NetConf{
			Name: "network_A",
			Type: "ovn-k8s-cni-overlay",
		},
		MTU: 1400,
	}
	network_A_incompatible := &ovncnitypes.NetConf{
		Topology: types.LocalnetTopology,
		NetConf: cnitypes.NetConf{
			Name: "network_A",
			Type: "ovn-k8s-cni-overlay",
		},
		MTU: 1400,
	}

	network_B := &ovncnitypes.NetConf{
		Topology: types.LocalnetTopology,
		NetConf: cnitypes.NetConf{
			Name: "network_B",
			Type: "ovn-k8s-cni-overlay",
		},
		MTU: 1400,
	}

	network_Default := &ovncnitypes.NetConf{
		Topology: types.Layer3Topology,
		NetConf: cnitypes.NetConf{
			Name: "default",
			Type: "ovn-k8s-cni-overlay",
		},
		MTU: 1400,
	}

	type args struct {
		nad     string
		network *ovncnitypes.NetConf
		wantErr bool
	}
	type expected struct {
		network *ovncnitypes.NetConf
		nads    []string
	}
	tests := []struct {
		name     string
		args     []args
		expected []expected
	}{
		{
			name: "NAD on default network should be skipped",
			args: []args{
				{
					nad:     "test/nad_1",
					network: network_Default,
				},
			},
			expected: []expected{},
		},
		{
			name: "NAD added",
			args: []args{
				{
					nad:     "test/nad_1",
					network: network_A,
				},
			},
			expected: []expected{
				{
					network: network_A,
					nads:    []string{"test/nad_1"},
				},
			},
		},
		{
			name: "NAD added then deleted",
			args: []args{
				{
					nad:     "test/nad_1",
					network: network_A,
				},
				{
					nad: "test/nad_1",
				},
			},
		},
		{
			name: "two NADs added",
			args: []args{
				{
					nad:     "test/nad_1",
					network: network_A,
				},
				{
					nad:     "test/nad_2",
					network: network_A,
				},
			},
			expected: []expected{
				{
					network: network_A,
					nads:    []string{"test/nad_1", "test/nad_2"},
				},
			},
		},
		{
			name: "two NADs added then one deleted",
			args: []args{
				{
					nad:     "test/nad_1",
					network: network_A,
				},
				{
					nad:     "test/nad_2",
					network: network_A,
				},
				{
					nad: "test/nad_1",
				},
			},
			expected: []expected{
				{
					network: network_A,
					nads:    []string{"test/nad_2"},
				},
			},
		},
		{
			name: "two NADs added then deleted",
			args: []args{
				{
					nad:     "test/nad_1",
					network: network_A,
				},
				{
					nad:     "test/nad_2",
					network: network_A,
				},
				{
					nad: "test/nad_2",
				},
				{
					nad: "test/nad_1",
				},
			},
		},
		{
			name: "NAD added then updated to different network",
			args: []args{
				{
					nad:     "test/nad_1",
					network: network_A,
				},
				{
					nad:     "test/nad_1",
					network: network_B,
				},
			},
			expected: []expected{
				{
					network: network_B,
					nads:    []string{"test/nad_1"},
				},
			},
		},
		{
			name: "two NADs added then one updated to different network",
			args: []args{
				{
					nad:     "test/nad_1",
					network: network_A,
				},
				{
					nad:     "test/nad_2",
					network: network_A,
				},
				{
					nad:     "test/nad_1",
					network: network_B,
				},
			},
			expected: []expected{
				{
					network: network_A,
					nads:    []string{"test/nad_2"},
				},
				{
					network: network_B,
					nads:    []string{"test/nad_1"},
				},
			},
		},
		{
			name: "two NADs added then one updated to same network",
			args: []args{
				{
					nad:     "test/nad_1",
					network: network_A,
				},
				{
					nad:     "test/nad_2",
					network: network_B,
				},
				{
					nad:     "test/nad_1",
					network: network_B,
				},
			},
			expected: []expected{
				{
					network: network_B,
					nads:    []string{"test/nad_1", "test/nad_2"},
				},
			},
		},
		{
			name: "NAD added then incompatible NAD added",
			args: []args{
				{
					nad:     "test/nad_1",
					network: network_A,
				},
				{
					nad:     "test/nad_2",
					network: network_A_incompatible,
					wantErr: true,
				},
			},
			expected: []expected{
				{
					network: network_A,
					nads:    []string{"test/nad_1"},
				},
			},
		},
		{
			name: "NAD added then updated to incompatible network",
			args: []args{
				{
					nad:     "test/nad_1",
					network: network_A,
				},
				{
					nad:     "test/nad_1",
					network: network_A_incompatible,
				},
			},
			expected: []expected{
				{
					network: network_A_incompatible,
					nads:    []string{"test/nad_1"},
				},
			},
		},
		{
			name: "two NADs added then one updated to incompatible network",
			args: []args{
				{
					nad:     "test/nad_1",
					network: network_A,
				},
				{
					nad:     "test/nad_2",
					network: network_A,
				},
				{
					nad:     "test/nad_1",
					network: network_A_incompatible,
					wantErr: true,
				},
			},
			expected: []expected{
				{
					network: network_A,
					nads:    []string{"test/nad_2"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			tncm := &testNetworkControllerManager{
				controllers: map[string]NetworkController{},
			}
			nadController := &NetAttachDefinitionController{
				networks:       map[string]util.NetInfo{},
				nads:           map[string]string{},
				networkManager: newNetworkManager("", tncm),
			}

			g.Expect(nadController.networkManager.Start()).To(gomega.Succeed())
			defer nadController.networkManager.Stop()

			for _, args := range tt.args {
				namespace, name, err := cache.SplitMetaNamespaceKey(args.nad)
				g.Expect(err).ToNot(gomega.HaveOccurred())

				var nad *nettypes.NetworkAttachmentDefinition
				if args.network != nil {
					args.network.NADName = args.nad
					nad, err = buildNAD(name, namespace, args.network)
					g.Expect(err).ToNot(gomega.HaveOccurred())
				}

				err = nadController.syncNAD(args.nad, nad)
				if args.wantErr {
					g.Expect(err).To(gomega.HaveOccurred())
				} else {
					g.Expect(err).NotTo(gomega.HaveOccurred())
				}
			}

			meetsExpectations := func(g gomega.Gomega) {
				tncm.Lock()
				defer tncm.Unlock()

				var expectRunning []string
				for _, expected := range tt.expected {
					netInfo, err := util.NewNetInfo(expected.network)
					g.Expect(err).ToNot(gomega.HaveOccurred())

					name := netInfo.GetNetworkName()
					testNetworkKey := testNetworkKey(netInfo)

					// test that the controller have the expected config and NADs
					g.Expect(tncm.controllers).To(gomega.HaveKey(testNetworkKey))
					g.Expect(tncm.controllers[testNetworkKey].Equals(netInfo)).To(gomega.BeTrue(),
						fmt.Sprintf("matching network config for network %s", name))
					g.Expect(tncm.controllers[testNetworkKey].GetNADs()).To(gomega.ConsistOf(expected.nads),
						fmt.Sprintf("matching NADs for network %s", name))
					expectRunning = append(expectRunning, testNetworkKey)
				}
				expectStopped := sets.New(tncm.started...).Difference(sets.New(expectRunning...)).UnsortedList()

				// test that the controllers are started, stopped and cleaned up as expected
				g.Expect(tncm.started).To(gomega.ContainElements(expectRunning), "started network controllers")
				g.Expect(tncm.stopped).To(gomega.ConsistOf(expectStopped), "stopped network controllers")
				g.Expect(tncm.cleaned).To(gomega.ConsistOf(expectStopped), "cleaned up network controllers")
			}

			g.Eventually(meetsExpectations).Should(gomega.Succeed())
			g.Consistently(meetsExpectations).Should(gomega.Succeed())
		})
	}
}

func TestSyncAll(t *testing.T) {
	network_A := &ovncnitypes.NetConf{
		Topology: types.Layer2Topology,
		NetConf: cnitypes.NetConf{
			Name: "network_A",
			Type: "ovn-k8s-cni-overlay",
		},
		MTU: 1400,
	}
	network_B := &ovncnitypes.NetConf{
		Topology: types.LocalnetTopology,
		NetConf: cnitypes.NetConf{
			Name: "network_B",
			Type: "ovn-k8s-cni-overlay",
		},
		MTU: 1400,
	}
	type TestNAD struct {
		name    string
		netconf *ovncnitypes.NetConf
	}
	tests := []struct {
		name     string
		testNADs []TestNAD
	}{
		{
			name: "multiple networks referenced by multiple nads",
			testNADs: []TestNAD{
				{
					name:    "test/nad1",
					netconf: network_A,
				},
				{
					name:    "test/nad2",
					netconf: network_B,
				},
				{
					name:    "test/nad3",
					netconf: network_A,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)

			config.OVNKubernetesFeature.EnableMultiNetwork = true
			fakeClient := util.GetOVNClientset().GetOVNKubeControllerClientset()
			wf, err := factory.NewOVNKubeControllerWatchFactory(fakeClient)
			g.Expect(err).ToNot(gomega.HaveOccurred())

			tncm := &testNetworkControllerManager{
				controllers: map[string]NetworkController{},
			}
			nadController, err := NewNetAttachDefinitionController(
				"SUT",
				tncm,
				wf,
			)
			g.Expect(err).ToNot(gomega.HaveOccurred())

			expectedNetworks := map[string]util.NetInfo{}
			for _, testNAD := range tt.testNADs {
				namespace, name, err := cache.SplitMetaNamespaceKey(testNAD.name)
				g.Expect(err).ToNot(gomega.HaveOccurred())
				testNAD.netconf.NADName = testNAD.name
				nad, err := buildNAD(name, namespace, testNAD.netconf)
				g.Expect(err).ToNot(gomega.HaveOccurred())
				_, err = fakeClient.NetworkAttchDefClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(namespace).Create(
					context.Background(),
					nad,
					v1.CreateOptions{},
				)
				g.Expect(err).ToNot(gomega.HaveOccurred())
				netInfo := expectedNetworks[testNAD.netconf.Name]
				if netInfo == nil {
					netInfo, err = util.NewNetInfo(testNAD.netconf)
					g.Expect(err).ToNot(gomega.HaveOccurred())
					expectedNetworks[testNAD.netconf.Name] = netInfo
				}
			}

			err = wf.Start()
			g.Expect(err).ToNot(gomega.HaveOccurred())
			defer wf.Shutdown()

			err = nadController.Start()
			g.Expect(err).ToNot(gomega.HaveOccurred())
			// sync has already happened, stop
			nadController.Stop()

			actualNetworks := map[string]util.BasicNetInfo{}
			for _, network := range tncm.valid {
				actualNetworks[network.GetNetworkName()] = network
			}

			g.Expect(actualNetworks).To(gomega.HaveLen(len(expectedNetworks)))
			for name, network := range expectedNetworks {
				g.Expect(actualNetworks).To(gomega.HaveKey(name))
				g.Expect(actualNetworks[name].Equals(network)).To(gomega.BeTrue())
			}
		})
	}
}

func buildNAD(name, namespace string, network *ovncnitypes.NetConf) (*nettypes.NetworkAttachmentDefinition, error) {
	config, err := json.Marshal(network)
	if err != nil {
		return nil, err
	}
	nad := &nettypes.NetworkAttachmentDefinition{
		ObjectMeta: v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: nettypes.NetworkAttachmentDefinitionSpec{
			Config: string(config),
		},
	}
	return nad, nil
}
