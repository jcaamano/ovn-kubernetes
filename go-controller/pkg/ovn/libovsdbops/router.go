package libovsdbops

import (
	"fmt"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/model"
	libovsdb "github.com/ovn-org/libovsdb/ovsdb"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
)

func findRouter(nbClient libovsdbclient.Client, router *nbdb.LogicalRouter) (string, error) {
	if router.UUID != "" && !IsNamedUUID(router.UUID) {
		return router.UUID, nil
	}

	routers := []nbdb.LogicalRouter{}
	err := nbClient.WhereCache(func(item *nbdb.LogicalRouter) bool {
		return item.Name == router.Name
	}).List(&routers)
	if err != nil {
		return "", fmt.Errorf("can't find router %+v: %v", *router, err)
	}

	if len(routers) > 1 {
		return "", fmt.Errorf("unexpectedly found multiple load balancers: %+v", routers)
	}

	if len(routers) == 1 {
		return routers[0].UUID, nil
	}

	return "", nil
}

func AddLoadBalancersToRouterOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, router *nbdb.LogicalRouter, lbs ...*nbdb.LoadBalancer) ([]libovsdb.Operation, error) {
	if ops == nil {
		ops = []libovsdb.Operation{}
	}

	uuid, err := findRouter(nbClient, router)
	if uuid == "" {
		return nil, err
	}
	router.UUID = uuid

	lbUUIDs := make([]string, 0, len(lbs))
	for _, lb := range lbs {
		lbUUIDs = append(lbUUIDs, lb.UUID)
	}

	op, err := nbClient.Where(router).Mutate(router, model.Mutation{
		Field:   &router.LoadBalancer,
		Mutator: libovsdb.MutateOperationInsert,
		Value:   lbUUIDs,
	})
	if err != nil {
		return nil, err
	}
	ops = append(ops, op...)

	return ops, nil
}

func RemoveLoadBalancersFromRouterOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, router *nbdb.LogicalRouter, lbs ...*nbdb.LoadBalancer) ([]libovsdb.Operation, error) {
	if ops == nil {
		ops = []libovsdb.Operation{}
	}

	uuid, err := findRouter(nbClient, router)
	if uuid == "" {
		return nil, err
	}
	router.UUID = uuid

	lbUUIDs := make([]string, 0, len(lbs))
	for _, lb := range lbs {
		lbUUIDs = append(lbUUIDs, lb.UUID)
	}

	op, err := nbClient.Where(router).Mutate(router, model.Mutation{
		Field:   &router.LoadBalancer,
		Mutator: libovsdb.MutateOperationDelete,
		Value:   lbUUIDs,
	})
	if err != nil {
		return nil, err
	}
	ops = append(ops, op...)

	return ops, nil
}
