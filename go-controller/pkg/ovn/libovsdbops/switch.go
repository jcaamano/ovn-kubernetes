package libovsdbops

import (
	"fmt"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/model"
	libovsdb "github.com/ovn-org/libovsdb/ovsdb"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
)

func findSwitch(nbClient libovsdbclient.Client, lswitch *nbdb.LogicalSwitch) (string, error) {
	if lswitch.UUID != "" && !IsNamedUUID(lswitch.UUID) {
		return lswitch.UUID, nil
	}

	switches := []nbdb.LogicalRouter{}
	err := nbClient.WhereCache(func(item *nbdb.LogicalRouter) bool {
		return item.Name == lswitch.Name
	}).List(&switches)
	if err != nil {
		return "", fmt.Errorf("can't find router %+v: %v", *lswitch, err)
	}

	if len(switches) > 1 {
		return "", fmt.Errorf("unexpectedly found multiple load balancers: %+v", switches)
	}

	if len(switches) == 1 {
		return switches[0].UUID, nil
	}

	return "", nil
}

func AddLoadBalancersToSwitchOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, lswitch *nbdb.LogicalSwitch, lbs ...*nbdb.LoadBalancer) ([]libovsdb.Operation, error) {
	if ops == nil {
		ops = []libovsdb.Operation{}
	}

	uuid, err := findSwitch(nbClient, lswitch)
	if uuid == "" {
		return nil, err
	}
	lswitch.UUID = uuid

	lbUUIDs := make([]string, 0, len(lbs))
	for _, lb := range lbs {
		lbUUIDs = append(lbUUIDs, lb.UUID)
	}

	op, err := nbClient.Where(lswitch).Mutate(lswitch, model.Mutation{
		Field:   &lswitch.LoadBalancer,
		Mutator: libovsdb.MutateOperationInsert,
		Value:   lbUUIDs,
	})
	if err != nil {
		return nil, err
	}
	ops = append(ops, op...)

	return ops, nil
}

func RemoveLoadBalancersFromSwitchOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, lswitch *nbdb.LogicalSwitch, lbs ...*nbdb.LoadBalancer) ([]libovsdb.Operation, error) {
	if ops == nil {
		ops = []libovsdb.Operation{}
	}

	uuid, err := findSwitch(nbClient, lswitch)
	if uuid == "" {
		return nil, err
	}
	lswitch.UUID = uuid

	lbUUIDs := make([]string, 0, len(lbs))
	for _, lb := range lbs {
		lbUUIDs = append(lbUUIDs, lb.UUID)
	}

	op, err := nbClient.Where(lswitch).Mutate(lswitch, model.Mutation{
		Field:   &lswitch.LoadBalancer,
		Mutator: libovsdb.MutateOperationDelete,
		Value:   lbUUIDs,
	})
	if err != nil {
		return nil, err
	}
	ops = append(ops, op...)

	return ops, nil
}
