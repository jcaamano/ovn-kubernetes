// Code generated by mockery v2.43.2. DO NOT EDIT.

package mocks

import (
	net "net"

	mock "github.com/stretchr/testify/mock"

	netlink "github.com/vishvananda/netlink"
)

// NetLinkOps is an autogenerated mock type for the NetLinkOps type
type NetLinkOps struct {
	mock.Mock
}

// AddrAdd provides a mock function with given fields: link, addr
func (_m *NetLinkOps) AddrAdd(link netlink.Link, addr *netlink.Addr) error {
	ret := _m.Called(link, addr)

	if len(ret) == 0 {
		panic("no return value specified for AddrAdd")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(netlink.Link, *netlink.Addr) error); ok {
		r0 = rf(link, addr)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AddrDel provides a mock function with given fields: link, addr
func (_m *NetLinkOps) AddrDel(link netlink.Link, addr *netlink.Addr) error {
	ret := _m.Called(link, addr)

	if len(ret) == 0 {
		panic("no return value specified for AddrDel")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(netlink.Link, *netlink.Addr) error); ok {
		r0 = rf(link, addr)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AddrList provides a mock function with given fields: link, family
func (_m *NetLinkOps) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	ret := _m.Called(link, family)

	if len(ret) == 0 {
		panic("no return value specified for AddrList")
	}

	var r0 []netlink.Addr
	var r1 error
	if rf, ok := ret.Get(0).(func(netlink.Link, int) ([]netlink.Addr, error)); ok {
		return rf(link, family)
	}
	if rf, ok := ret.Get(0).(func(netlink.Link, int) []netlink.Addr); ok {
		r0 = rf(link, family)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]netlink.Addr)
		}
	}

	if rf, ok := ret.Get(1).(func(netlink.Link, int) error); ok {
		r1 = rf(link, family)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ConntrackDeleteFilters provides a mock function with given fields: table, family, filters
func (_m *NetLinkOps) ConntrackDeleteFilters(table netlink.ConntrackTableType, family netlink.InetFamily, filters ...netlink.CustomConntrackFilter) (uint, error) {
	_va := make([]interface{}, len(filters))
	for _i := range filters {
		_va[_i] = filters[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, table, family)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for ConntrackDeleteFilters")
	}

	var r0 uint
	var r1 error
	if rf, ok := ret.Get(0).(func(netlink.ConntrackTableType, netlink.InetFamily, ...netlink.CustomConntrackFilter) (uint, error)); ok {
		return rf(table, family, filters...)
	}
	if rf, ok := ret.Get(0).(func(netlink.ConntrackTableType, netlink.InetFamily, ...netlink.CustomConntrackFilter) uint); ok {
		r0 = rf(table, family, filters...)
	} else {
		r0 = ret.Get(0).(uint)
	}

	if rf, ok := ret.Get(1).(func(netlink.ConntrackTableType, netlink.InetFamily, ...netlink.CustomConntrackFilter) error); ok {
		r1 = rf(table, family, filters...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IsLinkNotFoundError provides a mock function with given fields: err
func (_m *NetLinkOps) IsLinkNotFoundError(err error) bool {
	ret := _m.Called(err)

	if len(ret) == 0 {
		panic("no return value specified for IsLinkNotFoundError")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func(error) bool); ok {
		r0 = rf(err)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// LinkAdd provides a mock function with given fields: link
func (_m *NetLinkOps) LinkAdd(link netlink.Link) error {
	ret := _m.Called(link)

	if len(ret) == 0 {
		panic("no return value specified for LinkAdd")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(netlink.Link) error); ok {
		r0 = rf(link)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// LinkByIndex provides a mock function with given fields: index
func (_m *NetLinkOps) LinkByIndex(index int) (netlink.Link, error) {
	ret := _m.Called(index)

	if len(ret) == 0 {
		panic("no return value specified for LinkByIndex")
	}

	var r0 netlink.Link
	var r1 error
	if rf, ok := ret.Get(0).(func(int) (netlink.Link, error)); ok {
		return rf(index)
	}
	if rf, ok := ret.Get(0).(func(int) netlink.Link); ok {
		r0 = rf(index)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(netlink.Link)
		}
	}

	if rf, ok := ret.Get(1).(func(int) error); ok {
		r1 = rf(index)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// LinkByName provides a mock function with given fields: ifaceName
func (_m *NetLinkOps) LinkByName(ifaceName string) (netlink.Link, error) {
	ret := _m.Called(ifaceName)

	if len(ret) == 0 {
		panic("no return value specified for LinkByName")
	}

	var r0 netlink.Link
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (netlink.Link, error)); ok {
		return rf(ifaceName)
	}
	if rf, ok := ret.Get(0).(func(string) netlink.Link); ok {
		r0 = rf(ifaceName)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(netlink.Link)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(ifaceName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// LinkDelete provides a mock function with given fields: link
func (_m *NetLinkOps) LinkDelete(link netlink.Link) error {
	ret := _m.Called(link)

	if len(ret) == 0 {
		panic("no return value specified for LinkDelete")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(netlink.Link) error); ok {
		r0 = rf(link)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// LinkList provides a mock function with given fields:
func (_m *NetLinkOps) LinkList() ([]netlink.Link, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for LinkList")
	}

	var r0 []netlink.Link
	var r1 error
	if rf, ok := ret.Get(0).(func() ([]netlink.Link, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() []netlink.Link); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]netlink.Link)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// LinkSetDown provides a mock function with given fields: link
func (_m *NetLinkOps) LinkSetDown(link netlink.Link) error {
	ret := _m.Called(link)

	if len(ret) == 0 {
		panic("no return value specified for LinkSetDown")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(netlink.Link) error); ok {
		r0 = rf(link)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// LinkSetHardwareAddr provides a mock function with given fields: link, hwaddr
func (_m *NetLinkOps) LinkSetHardwareAddr(link netlink.Link, hwaddr net.HardwareAddr) error {
	ret := _m.Called(link, hwaddr)

	if len(ret) == 0 {
		panic("no return value specified for LinkSetHardwareAddr")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(netlink.Link, net.HardwareAddr) error); ok {
		r0 = rf(link, hwaddr)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// LinkSetMTU provides a mock function with given fields: link, mtu
func (_m *NetLinkOps) LinkSetMTU(link netlink.Link, mtu int) error {
	ret := _m.Called(link, mtu)

	if len(ret) == 0 {
		panic("no return value specified for LinkSetMTU")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(netlink.Link, int) error); ok {
		r0 = rf(link, mtu)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// LinkSetMaster provides a mock function with given fields: link, master
func (_m *NetLinkOps) LinkSetMaster(link netlink.Link, master netlink.Link) error {
	ret := _m.Called(link, master)

	if len(ret) == 0 {
		panic("no return value specified for LinkSetMaster")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(netlink.Link, netlink.Link) error); ok {
		r0 = rf(link, master)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// LinkSetName provides a mock function with given fields: link, newName
func (_m *NetLinkOps) LinkSetName(link netlink.Link, newName string) error {
	ret := _m.Called(link, newName)

	if len(ret) == 0 {
		panic("no return value specified for LinkSetName")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(netlink.Link, string) error); ok {
		r0 = rf(link, newName)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// LinkSetNoMaster provides a mock function with given fields: link
func (_m *NetLinkOps) LinkSetNoMaster(link netlink.Link) error {
	ret := _m.Called(link)

	if len(ret) == 0 {
		panic("no return value specified for LinkSetNoMaster")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(netlink.Link) error); ok {
		r0 = rf(link)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// LinkSetNsFd provides a mock function with given fields: link, fd
func (_m *NetLinkOps) LinkSetNsFd(link netlink.Link, fd int) error {
	ret := _m.Called(link, fd)

	if len(ret) == 0 {
		panic("no return value specified for LinkSetNsFd")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(netlink.Link, int) error); ok {
		r0 = rf(link, fd)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// LinkSetTxQLen provides a mock function with given fields: link, qlen
func (_m *NetLinkOps) LinkSetTxQLen(link netlink.Link, qlen int) error {
	ret := _m.Called(link, qlen)

	if len(ret) == 0 {
		panic("no return value specified for LinkSetTxQLen")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(netlink.Link, int) error); ok {
		r0 = rf(link, qlen)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// LinkSetUp provides a mock function with given fields: link
func (_m *NetLinkOps) LinkSetUp(link netlink.Link) error {
	ret := _m.Called(link)

	if len(ret) == 0 {
		panic("no return value specified for LinkSetUp")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(netlink.Link) error); ok {
		r0 = rf(link)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// LinkSetVfHardwareAddr provides a mock function with given fields: pfLink, vfIndex, hwaddr
func (_m *NetLinkOps) LinkSetVfHardwareAddr(pfLink netlink.Link, vfIndex int, hwaddr net.HardwareAddr) error {
	ret := _m.Called(pfLink, vfIndex, hwaddr)

	if len(ret) == 0 {
		panic("no return value specified for LinkSetVfHardwareAddr")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(netlink.Link, int, net.HardwareAddr) error); ok {
		r0 = rf(pfLink, vfIndex, hwaddr)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// LinkSubscribeWithOptions provides a mock function with given fields: ch, done, options
func (_m *NetLinkOps) LinkSubscribeWithOptions(ch chan<- netlink.LinkUpdate, done <-chan struct{}, options netlink.LinkSubscribeOptions) error {
	ret := _m.Called(ch, done, options)

	if len(ret) == 0 {
		panic("no return value specified for LinkSubscribeWithOptions")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(chan<- netlink.LinkUpdate, <-chan struct{}, netlink.LinkSubscribeOptions) error); ok {
		r0 = rf(ch, done, options)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NeighAdd provides a mock function with given fields: neigh
func (_m *NetLinkOps) NeighAdd(neigh *netlink.Neigh) error {
	ret := _m.Called(neigh)

	if len(ret) == 0 {
		panic("no return value specified for NeighAdd")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*netlink.Neigh) error); ok {
		r0 = rf(neigh)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NeighDel provides a mock function with given fields: neigh
func (_m *NetLinkOps) NeighDel(neigh *netlink.Neigh) error {
	ret := _m.Called(neigh)

	if len(ret) == 0 {
		panic("no return value specified for NeighDel")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*netlink.Neigh) error); ok {
		r0 = rf(neigh)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NeighList provides a mock function with given fields: linkIndex, family
func (_m *NetLinkOps) NeighList(linkIndex int, family int) ([]netlink.Neigh, error) {
	ret := _m.Called(linkIndex, family)

	if len(ret) == 0 {
		panic("no return value specified for NeighList")
	}

	var r0 []netlink.Neigh
	var r1 error
	if rf, ok := ret.Get(0).(func(int, int) ([]netlink.Neigh, error)); ok {
		return rf(linkIndex, family)
	}
	if rf, ok := ret.Get(0).(func(int, int) []netlink.Neigh); ok {
		r0 = rf(linkIndex, family)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]netlink.Neigh)
		}
	}

	if rf, ok := ret.Get(1).(func(int, int) error); ok {
		r1 = rf(linkIndex, family)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RouteAdd provides a mock function with given fields: route
func (_m *NetLinkOps) RouteAdd(route *netlink.Route) error {
	ret := _m.Called(route)

	if len(ret) == 0 {
		panic("no return value specified for RouteAdd")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*netlink.Route) error); ok {
		r0 = rf(route)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RouteDel provides a mock function with given fields: route
func (_m *NetLinkOps) RouteDel(route *netlink.Route) error {
	ret := _m.Called(route)

	if len(ret) == 0 {
		panic("no return value specified for RouteDel")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*netlink.Route) error); ok {
		r0 = rf(route)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RouteList provides a mock function with given fields: link, family
func (_m *NetLinkOps) RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	ret := _m.Called(link, family)

	if len(ret) == 0 {
		panic("no return value specified for RouteList")
	}

	var r0 []netlink.Route
	var r1 error
	if rf, ok := ret.Get(0).(func(netlink.Link, int) ([]netlink.Route, error)); ok {
		return rf(link, family)
	}
	if rf, ok := ret.Get(0).(func(netlink.Link, int) []netlink.Route); ok {
		r0 = rf(link, family)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]netlink.Route)
		}
	}

	if rf, ok := ret.Get(1).(func(netlink.Link, int) error); ok {
		r1 = rf(link, family)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RouteListFiltered provides a mock function with given fields: family, filter, filterMask
func (_m *NetLinkOps) RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	ret := _m.Called(family, filter, filterMask)

	if len(ret) == 0 {
		panic("no return value specified for RouteListFiltered")
	}

	var r0 []netlink.Route
	var r1 error
	if rf, ok := ret.Get(0).(func(int, *netlink.Route, uint64) ([]netlink.Route, error)); ok {
		return rf(family, filter, filterMask)
	}
	if rf, ok := ret.Get(0).(func(int, *netlink.Route, uint64) []netlink.Route); ok {
		r0 = rf(family, filter, filterMask)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]netlink.Route)
		}
	}

	if rf, ok := ret.Get(1).(func(int, *netlink.Route, uint64) error); ok {
		r1 = rf(family, filter, filterMask)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RouteReplace provides a mock function with given fields: route
func (_m *NetLinkOps) RouteReplace(route *netlink.Route) error {
	ret := _m.Called(route)

	if len(ret) == 0 {
		panic("no return value specified for RouteReplace")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*netlink.Route) error); ok {
		r0 = rf(route)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RouteSubscribeWithOptions provides a mock function with given fields: ch, done, options
func (_m *NetLinkOps) RouteSubscribeWithOptions(ch chan<- netlink.RouteUpdate, done <-chan struct{}, options netlink.RouteSubscribeOptions) error {
	ret := _m.Called(ch, done, options)

	if len(ret) == 0 {
		panic("no return value specified for RouteSubscribeWithOptions")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(chan<- netlink.RouteUpdate, <-chan struct{}, netlink.RouteSubscribeOptions) error); ok {
		r0 = rf(ch, done, options)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RuleListFiltered provides a mock function with given fields: family, filter, filterMask
func (_m *NetLinkOps) RuleListFiltered(family int, filter *netlink.Rule, filterMask uint64) ([]netlink.Rule, error) {
	ret := _m.Called(family, filter, filterMask)

	if len(ret) == 0 {
		panic("no return value specified for RuleListFiltered")
	}

	var r0 []netlink.Rule
	var r1 error
	if rf, ok := ret.Get(0).(func(int, *netlink.Rule, uint64) ([]netlink.Rule, error)); ok {
		return rf(family, filter, filterMask)
	}
	if rf, ok := ret.Get(0).(func(int, *netlink.Rule, uint64) []netlink.Rule); ok {
		r0 = rf(family, filter, filterMask)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]netlink.Rule)
		}
	}

	if rf, ok := ret.Get(1).(func(int, *netlink.Rule, uint64) error); ok {
		r1 = rf(family, filter, filterMask)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewNetLinkOps creates a new instance of NetLinkOps. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewNetLinkOps(t interface {
	mock.TestingT
	Cleanup(func())
}) *NetLinkOps {
	mock := &NetLinkOps{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
