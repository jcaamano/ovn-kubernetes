package loadbalancer

import (
	"fmt"
	"log"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	libovsdb "github.com/ovn-org/libovsdb/ovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/libovsdbops"

	"k8s.io/klog/v2"
)

// EnsureLBs provides a generic load-balancer reconciliation engine.
//
// It assures that, for a given set of ExternalIDs, only the configured
// list of load balancers exist. Existing load-balancers will be updated,
// new ones will be created as needed, and stale ones will be deleted.
//
// For example, you might want to ensure that service ns/foo has the
// correct set of load balancers. You would call it with something like
//
//     EnsureLBs( { kind: Service, owner: ns/foo}, { {Name: Service_ns/foo_cluster_tcp, ...}})
//
// This will ensure that, for this example, only that one LB exists and
// has the desired configuration.
//
// It will commit all updates in a single transaction, so updates will be
// atomic and users should see no disruption. However, concurrent calls
// that modify the same externalIDs are not allowed.
//
// It is assumed that names are meaningful and somewhat stable, to minimize churn. This
// function doesn't work with Load_Balancers without a name.
func EnsureLBs(nbClient libovsdbclient.Client, externalIDs map[string]string, LBs []LB) error {
	lbCache, err := GetLBCache(nbClient)
	if err != nil {
		return fmt.Errorf("failed initialize LBcache: %w", err)
	}

	existing := lbCache.Find(externalIDs)
	log.Printf("existing LBS: %+v", existing)
	log.Printf("wanted LBs: %+v", LBs)
	existingByName := make(map[string]*CachedLB, len(existing))
	toDelete := sets.NewString()

	for _, lb := range existing {
		existingByName[lb.Name] = lb
		toDelete.Insert(lb.UUID)
	}

	lbs := make([]*nbdb.LoadBalancer, 0, len(LBs))
	addLBsToSwitch := map[string][]*nbdb.LoadBalancer{}
	removeLBsFromSwitch := map[string][]*nbdb.LoadBalancer{}
	addLBsToRouter := map[string][]*nbdb.LoadBalancer{}
	removesLBsFromRouter := map[string][]*nbdb.LoadBalancer{}
	wantedByName := make(map[string]*LB, len(LBs))
	for i, lb := range LBs {
		wantedByName[lb.Name] = &LBs[i]
		blb := buildLB(&lb)
		lbs = append(lbs, blb)
		existingLB := existingByName[lb.Name]
		existingRouters := sets.String{}
		existingSwitches := sets.String{}
		if existingLB != nil {
			toDelete.Delete(existingLB.UUID)
			existingRouters = existingLB.Routers
			existingSwitches = existingLB.Switches
		}
		wantRouters := sets.NewString(lb.Routers...)
		wantSwitches := sets.NewString(lb.Switches...)
		mapLBDifferenceByKey(addLBsToSwitch, wantSwitches, existingSwitches, blb)
		mapLBDifferenceByKey(removeLBsFromSwitch, existingSwitches, wantSwitches, blb)
		mapLBDifferenceByKey(addLBsToRouter, wantRouters, existingRouters, blb)
		mapLBDifferenceByKey(removesLBsFromRouter, existingRouters, wantRouters, blb)
	}

	ops, err := libovsdbops.CreateOrUpdateLoadBalancersOps(nbClient, nil, lbs...)
	if err != nil {
		return err
	}

	// cache switches for this round of ops
	lswitches := map[string]*nbdb.LogicalSwitch{}
	getSwitch := func(name string) *nbdb.LogicalSwitch {
		var lswitch *nbdb.LogicalSwitch
		var found bool
		if lswitch, found = lswitches[name]; !found {
			lswitch = &nbdb.LogicalSwitch{Name: name}
			lswitches[name] = lswitch
		}
		return lswitch
	}
	for k, v := range addLBsToSwitch {
		ops, err = libovsdbops.AddLoadBalancersToSwitchOps(nbClient, ops, getSwitch(k), v...)
		if err != nil {
			return err
		}
	}
	for k, v := range removeLBsFromSwitch {
		ops, err = libovsdbops.RemoveLoadBalancersFromSwitchOps(nbClient, ops, getSwitch(k), v...)
		if err != nil {
			return err
		}
	}

	// cache routers for this round of ops
	routers := map[string]*nbdb.LogicalRouter{}
	getRouter := func(name string) *nbdb.LogicalRouter {
		var router *nbdb.LogicalRouter
		var found bool
		if router, found = routers[name]; !found {
			router = &nbdb.LogicalRouter{Name: name}
			routers[name] = router
		}
		return router
	}
	for k, v := range addLBsToRouter {
		ops, err = libovsdbops.AddLoadBalancersToRouterOps(nbClient, ops, getRouter(k), v...)
		if err != nil {
			return err
		}
	}
	for k, v := range removesLBsFromRouter {
		ops, err = libovsdbops.RemoveLoadBalancersFromRouterOps(nbClient, ops, getRouter(k), v...)
		if err != nil {
			return err
		}
	}

	deleteLBs := make([]*nbdb.LoadBalancer, 0, len(toDelete))
	for uuid := range toDelete {
		deleteLBs = append(deleteLBs, &nbdb.LoadBalancer{UUID: uuid})
	}
	ops, err = libovsdbops.DeleteLoadBalancersOps(nbClient, ops, deleteLBs...)

	_, err = libovsdbops.TransactAndCheckAndSetUUIDs(nbClient, lbs, ops)
	if err != nil {
		return err
	}

	for _, lb := range lbs {
		log.Printf("Setting uuid %s for %s", lb.UUID, lb.Name)
		wantedByName[lb.Name].UUID = lb.UUID
	}

	lbCache.update(LBs, toDelete.UnsortedList())
	klog.V(5).Infof("Deleted %d stale LBs for %#v", len(toDelete), externalIDs)

	return nil
}

func mapLBDifferenceByKey(keyMap map[string][]*nbdb.LoadBalancer, keyIn sets.String, keyNotIn sets.String, lb *nbdb.LoadBalancer) {
	for _, k := range keyIn.Difference(keyNotIn).UnsortedList() {
		l := keyMap[k]
		if l == nil {
			l = []*nbdb.LoadBalancer{}
		}
		l = append(l, lb)
		keyMap[k] = l
	}
}

func buildLB(lb *LB) *nbdb.LoadBalancer {
	reject := "true"
	event := "false"

	if lb.Opts.Unidling {
		reject = "false"
		event = "true"
	}

	skipSNAT := "false"
	if lb.Opts.SkipSNAT {
		skipSNAT = "true"
	}

	options := map[string]string{
		"reject":    reject,
		"event":     event,
		"skip_snat": skipSNAT,
	}

	// Session affinity
	// If enabled, then bucket flows by 3-tuple (proto, srcip, dstip)
	// otherwise, use default ovn value
	var selectionFields []nbdb.LoadBalancerSelectionFields
	if lb.Opts.Affinity {
		selectionFields = []string{
			nbdb.LoadBalancerSelectionFieldsIPSrc,
			nbdb.LoadBalancerSelectionFieldsIPSrc,
		}
	}

	// vipMap
	vips := buildVipMap(lb.Rules)

	return libovsdbops.BuildLoadBalancer(lb.Name, strings.ToLower(lb.Protocol), selectionFields, vips, options, lb.ExternalIDs)
}

// buildVipMap returns a viups map from a set of rules
func buildVipMap(rules []LBRule) map[string]string {
	vipMap := make(map[string]string, len(rules))
	for _, r := range rules {
		tgts := make([]string, 0, len(r.Targets))
		for _, tgt := range r.Targets {
			tgts = append(tgts, tgt.String())
		}
		vipMap[r.Source.String()] = strings.Join(tgts, ",")
	}

	return vipMap
}

// DeleteLBs deletes all load balancer uuids supplied
// Note: this also automatically removes them from the switches and the routers :-)
func DeleteLBs(nbClient libovsdbclient.Client, uuids []string) error {
	if len(uuids) == 0 {
		return nil
	}

	cache, err := GetLBCache(nbClient)
	if err != nil {
		return err
	}

	lbs := make([]*nbdb.LoadBalancer, 0, len(uuids))
	for _, uuid := range uuids {
		lbs = append(lbs, &nbdb.LoadBalancer{UUID: uuid})
	}

	err = libovsdbops.DeleteLoadBalancers(nbClient, lbs)
	if err != nil {
		return err
	}

	cache.update(nil, uuids)
	return nil
}

type DeleteVIPEntry struct {
	LBUUID string
	VIPs   []string // ip:string (or v6 equivalent)
}

// DeleteLoadBalancerVIPs removes VIPs from load-balancers in a single shot.
func DeleteLoadBalancerVIPs(nbClient libovsdbclient.Client, toRemove []DeleteVIPEntry) error {
	lbCache, err := GetLBCache(nbClient)
	if err != nil {
		return err
	}

	var ops []libovsdb.Operation
	for _, entry := range toRemove {
		ops, err = libovsdbops.RemoveLoadBalancerVipsOps(nbClient, ops, &nbdb.LoadBalancer{UUID: entry.LBUUID}, entry.VIPs...)
	}

	_, err = libovsdbops.TransactAndCheck(nbClient, ops)
	if err != nil {
		return fmt.Errorf("failed to remove vips from load_balancer: %w", err)
	}

	lbCache.removeVips(toRemove)

	return nil
}
