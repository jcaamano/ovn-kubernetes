package libovsdbops

import (
	"fmt"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/model"
	libovsdb "github.com/ovn-org/libovsdb/ovsdb"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
)

func findLoadBalancer(nbClient libovsdbclient.Client, lb *nbdb.LoadBalancer) (string, error) {
	if lb.UUID != "" && !IsNamedUUID(lb.UUID) {
		return lb.UUID, nil
	}

	lbs := []nbdb.LoadBalancer{}
	err := nbClient.WhereCache(func(item *nbdb.LoadBalancer) bool {
		return item.Name == lb.Name
	}).List(&lbs)
	if err != nil {
		return "", fmt.Errorf("can't find load balancer %+v: %v", *lb, err)
	}

	if len(lbs) > 1 {
		return "", fmt.Errorf("unexpectedly found multiple load balancers: %+v", lbs)
	}

	if len(lbs) == 1 {
		return lbs[0].UUID, nil
	}

	return "", nil
}

func BuildLoadBalancer(name string, protocol nbdb.LoadBalancerProtocol, selectionFields []nbdb.LoadBalancerSelectionFields, vips, options, externalIds map[string]string) *nbdb.LoadBalancer {
	return &nbdb.LoadBalancer{
		UUID:            BuildNamedUUID(),
		Name:            name,
		Protocol:        &protocol,
		SelectionFields: selectionFields,
		Vips:            vips,
		Options:         options,
		ExternalIDs:     externalIds,
	}
}

func createOrUpdateLoadBalancerOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, lb *nbdb.LoadBalancer) ([]libovsdb.Operation, error) {
	if ops == nil {
		ops = []libovsdb.Operation{}
	}

	uuid, err := findLoadBalancer(nbClient, lb)
	if err != nil {
		return nil, err
	}

	// If ACL already exists, update it
	if uuid != "" {
		lb.UUID = ""
		op, err := nbClient.Where(&nbdb.ACL{UUID: uuid}).Update(lb)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op...)
		lb.UUID = uuid
		return ops, nil
	}

	op, err := nbClient.Create(lb)
	if err != nil {
		return nil, err
	}
	ops = append(ops, op...)

	return ops, nil
}

func CreateOrUpdateLoadBalancersOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, lbs ...*nbdb.LoadBalancer) ([]libovsdb.Operation, error) {
	if ops == nil {
		ops = []libovsdb.Operation{}
	}
	for _, lb := range lbs {
		var err error
		ops, err = createOrUpdateLoadBalancerOps(nbClient, ops, lb)
		if err != nil {
			return nil, err
		}
	}

	return ops, nil
}

func CreateOrUpdateLoadBalancers(nbClient libovsdbclient.Client, lbs ...*nbdb.LoadBalancer) error {
	ops, err := CreateOrUpdateLoadBalancersOps(nbClient, nil, lbs...)
	if err != nil {
		return err
	}

	_, err = TransactAndCheck(nbClient, ops)
	if err != nil {
		return err
	}
	return nil
}

func RemoveLoadBalancerVipsOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, lb *nbdb.LoadBalancer, vips ...string) ([]libovsdb.Operation, error) {
	if ops == nil {
		ops = []libovsdb.Operation{}
	}

	uuid, err := findLoadBalancer(nbClient, lb)
	if err != nil {
		return nil, err
	}
	lb.UUID = uuid

	vipMap := make(map[string]string, len(vips))
	for _, vip := range vips {
		vipMap[vip] = ""
	}

	op, err := nbClient.Where(lb).Mutate(lb, model.Mutation{
		Field:   &lb.Vips,
		Mutator: libovsdb.MutateOperationDelete,
		Value:   vipMap,
	})
	if err != nil {
		return nil, err
	}
	ops = append(ops, op...)

	return ops, nil
}

func RemoveLoadBalancerVips(nbClient libovsdbclient.Client, lb *nbdb.LoadBalancer, vips ...string) error {
	ops, err := RemoveLoadBalancerVipsOps(nbClient, nil, lb, vips...)
	if err != nil {
		return err
	}

	_, err = TransactAndCheck(nbClient, ops)
	return err
}

func deleteLoadBalancerOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, lb *nbdb.LoadBalancer) ([]libovsdb.Operation, error) {
	if ops == nil {
		ops = []libovsdb.Operation{}
	}

	uuid, err := findLoadBalancer(nbClient, lb)
	if err != nil {
		return nil, err
	}
	lb.UUID = uuid

	op, err := nbClient.Where(lb).Delete()
	if err != nil {
		return nil, err
	}
	ops = append(ops, op...)

	return ops, nil
}

func DeleteLoadBalancersOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, lbs ...*nbdb.LoadBalancer) ([]libovsdb.Operation, error) {
	if ops == nil {
		ops = []libovsdb.Operation{}
	}
	var err error
	for _, lb := range lbs {
		ops, err = deleteLoadBalancerOps(nbClient, ops, lb)
		if err != nil {
			return nil, err
		}
	}

	return ops, nil
}

func DeleteLoadBalancers(nbClient libovsdbclient.Client, lbs []*nbdb.LoadBalancer) error {
	ops, err := DeleteLoadBalancersOps(nbClient, nil, lbs...)
	if err != nil {
		return err
	}

	_, err = TransactAndCheck(nbClient, ops)
	return err
}
