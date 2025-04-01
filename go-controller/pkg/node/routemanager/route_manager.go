package routemanager

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

// MainTableID is the default routing table. IPRoute2 names the default routing table as 'main'
const MainTableID = 254

type Controller struct {
	*sync.Mutex
	store map[int][]netlink.Route // key is link index
}

// NewController manages routes which include adding and deletion of routes. It also manages restoration of managed routes.
// Begin managing routes by calling Run() to start the manager.
// Routes should be added via add(route) and deletion via del(route) functions only.
// All other functions are used internally.
func NewController() *Controller {
	return &Controller{
		Mutex: &sync.Mutex{},
		store: make(map[int][]netlink.Route),
	}
}

// Run starts route manager and syncs at least every syncPeriod
func (c *Controller) Run(stopCh <-chan struct{}, syncPeriod time.Duration) {
	var err error
	var subscribed bool
	var routeEventCh chan netlink.RouteUpdate
	// netlink provides subscribing only to route events from the default table. Periodic sync will restore non-main table routes
	subscribed, routeEventCh = subscribeNetlinkRouteEvents(stopCh)
	ticker := time.NewTicker(syncPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			// continue existing behaviour of not cleaning up routes upon exit
			return
		case newRouteEvent, ok := <-routeEventCh:
			if !ok {
				klog.Info("Route Manager: failed to read netlink route event - resubscribing")
				subscribed, routeEventCh = subscribeNetlinkRouteEvents(stopCh)
				continue
			}
			if err = c.processNetlinkEvent(newRouteEvent); err != nil {
				// TODO: make util.GetNetLinkOps().IsLinkNotFoundError(err) smarter to unwrap error
				// and use it here to log errors that are not IsLinkNotFoundError
				klog.V(5).Infof("Route Manager: failed to process route update event (%s): %v", newRouteEvent.String(), err)
			}
		case <-ticker.C:
			if !subscribed {
				klog.Info("Route Manager: netlink route events aren't subscribed - resubscribing")
				subscribed, routeEventCh = subscribeNetlinkRouteEvents(stopCh)
			}
			c.sync()
		}
	}
}

// Add submits a request to add a route
func (c *Controller) Add(r netlink.Route) error {
	if err := c.addRoute(r); err != nil {
		return fmt.Errorf("route manager: failed to add route (%s): %w", r.String(), err)
	}
	return nil
}

// Del submits a request to del a route
func (c *Controller) Del(r netlink.Route) error {
	if err := c.delRoute(r); err != nil {
		return fmt.Errorf("route manager: failed to delete route (%s): %v", r.String(), err)
	}
	return nil
}

// addRoute attempts to add the route and returns with error
// if it fails to do so.
func (c *Controller) addRoute(r netlink.Route) error {
	c.Lock()
	defer c.Unlock()
	klog.Infof("Route Manager: attempting to add route: %s", r.String())
	// If table is unspecified aka 0, then set it to main table ID. This is done by default when adding a route.
	// Set it explicitly to aid comparison of routes.
	if r.Table == 0 {
		r.Table = MainTableID
	}
	if addedToStore := c.addRouteToStore(r); !addedToStore {
		// already managed - nothing to do
		return nil
	}
	link, err := util.GetNetLinkOps().LinkByIndex(r.LinkIndex)
	if err != nil {
		return fmt.Errorf("failed to apply route (%s) because unable to get link: %v", r.String(), err)
	}
	if err := c.applyRoute(link, r.Gw, r.Dst, r.MTU, r.Src, r.Table, r.Priority, r.Type, r.Scope); err != nil {
		return fmt.Errorf("failed to apply route (%s): %v", r.String(), err)
	}
	klog.Infof("Route Manager: completed adding route: %s", r.String())
	return nil
}

// delRoute attempts to remove the route and returns with error
// if it fails to do so.
func (c *Controller) delRoute(r netlink.Route) error {
	c.Lock()
	defer c.Unlock()
	klog.Infof("Route Manager: attempting to delete route: %s", r.String())
	link, err := util.GetNetLinkOps().LinkByIndex(r.LinkIndex)
	if err != nil {
		if util.GetNetLinkOps().IsLinkNotFoundError(err) {
			delete(c.store, r.LinkIndex)
			return nil
		}
		return fmt.Errorf("failed to delete route (%s) because unable to get link: %v", r.String(), err)
	}
	if err := c.netlinkDelRoute(link, r.Dst, r.Table, r.Type); err != nil {
		return fmt.Errorf("failed to delete route (%s): %v", r.String(), err)
	}
	managedRoutes, ok := c.store[r.LinkIndex]
	if !ok {
		return nil
	}
	// remove route from existing routes
	managedRoutesTemp := make([]netlink.Route, 0, len(managedRoutes))
	for _, managedRoute := range managedRoutes {
		if !RoutePartiallyEqual(managedRoute, r) {
			managedRoutesTemp = append(managedRoutesTemp, managedRoute)
		}
	}
	if len(managedRoutesTemp) == 0 {
		delete(c.store, r.LinkIndex)
	} else {
		c.store[r.LinkIndex] = managedRoutesTemp
	}
	klog.Infof("Route Manager: deletion of routes for link complete: %s", r.String())
	return nil
}

// processNetlinkEvent will check if a deleted route is managed by route manager and if so, determine if a sync is needed
// to restore any managed routes.
func (c *Controller) processNetlinkEvent(ru netlink.RouteUpdate) error {
	c.Lock()
	defer c.Unlock()
	if ru.Type == unix.RTM_NEWROUTE {
		// An event resulting from `ip route change` will be seen as type RTM_NEWROUTE event and therefore this function will only
		// log the changes and not attempt to restore the change. This will be accomplished by the sync function.
		klog.Infof("Route Manager: netlink route addition event: %q", ru.String())
		return nil
	}
	if ru.Type != unix.RTM_DELROUTE {
		return nil
	}
	klog.V(5).Infof("Route Manager: netlink route deletion event: %q", ru.String())
	managedRoutes, ok := c.store[ru.LinkIndex]
	if !ok {
		// we don't manage this interface
		return nil
	}
	for _, managedRoute := range managedRoutes {
		if RoutePartiallyEqual(managedRoute, ru.Route) {
			link, err := util.GetNetLinkOps().LinkByIndex(managedRoute.LinkIndex)
			if err != nil {
				klog.Errorf("Route Manager: failed to restore route because unable to get link by index %d: %v", managedRoute.LinkIndex, err)
				continue
			}
			if err = c.applyRoute(link, managedRoute.Gw, managedRoute.Dst, managedRoute.MTU, managedRoute.Src, managedRoute.Table,
				managedRoute.Priority, managedRoute.Type, managedRoute.Scope); err != nil {
				klog.Errorf("Route Manager: failed to apply route (%s): %v", managedRoute.String(), err)
			}
		}
	}
	return nil
}

func (c *Controller) applyRoute(link netlink.Link, gwIP net.IP, subnet *net.IPNet, mtu int, src net.IP,
	table, priority, rtype int, scope netlink.Scope) error {
	filterRoute, filterMask := filterRouteByDstAndTable(link.Attrs().Index, subnet, table)
	filterRoute = updateLinkIndexBasedOnRouteTypes(rtype, subnet, filterRoute)
	existingRoutes, err := util.GetNetLinkOps().RouteListFiltered(getNetlinkIPFamily(subnet), filterRoute, filterMask)
	if err != nil {
		return fmt.Errorf("failed to list filtered routes: %v", err)
	}
	if len(existingRoutes) == 0 {
		return c.netlinkAddRoute(link, gwIP, subnet, mtu, src, table, priority, rtype, scope)
	}
	netlinkRoute := &existingRoutes[0]
	if netlinkRoute.MTU != mtu || !src.Equal(netlinkRoute.Src) || !gwIP.Equal(netlinkRoute.Gw) {
		netlinkRoute.MTU = mtu
		netlinkRoute.Src = src
		netlinkRoute.Gw = gwIP
		err = util.GetNetLinkOps().RouteReplace(netlinkRoute)
		if err != nil {
			return fmt.Errorf("failed to replace route for subnet %s via gateway %s with mtu %d: %v",
				subnet.String(), gwIP.String(), mtu, err)
		}
	}
	return nil
}

func (c *Controller) netlinkAddRoute(link netlink.Link, gwIP net.IP, subnet *net.IPNet,
	mtu int, srcIP net.IP, table, priority, rtype int, scope netlink.Scope) error {
	newNlRoute := &netlink.Route{
		Dst:       subnet,
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Table:     table,
	}
	if len(gwIP) > 0 {
		newNlRoute.Gw = gwIP
	}
	if len(srcIP) > 0 {
		newNlRoute.Src = srcIP
	}
	if mtu != 0 {
		newNlRoute.MTU = mtu
	}
	if priority != 0 {
		newNlRoute.Priority = priority
	}
	if rtype != 0 {
		newNlRoute.Type = rtype
	}
	if scope != netlink.Scope(0) {
		newNlRoute.Scope = scope
	}
	// set link index for unreachable or blackhole route to avoid unexpected error.
	newNlRoute = updateLinkIndexBasedOnRouteTypes(rtype, subnet, newNlRoute)
	err := util.GetNetLinkOps().RouteAdd(newNlRoute)
	if err != nil {
		return fmt.Errorf("failed to add route (linkIndex: %d gw: %v, subnet %v, mtu %d, src IP %v): %v",
			newNlRoute.LinkIndex, gwIP, subnet, mtu, srcIP, err)
	}
	return nil
}

func (c *Controller) netlinkDelRoute(link netlink.Link, subnet *net.IPNet, table, rtype int) error {
	if subnet == nil {
		return fmt.Errorf("cannot delete route with no valid subnet")
	}
	filter, mask := filterRouteByDstAndTable(link.Attrs().Index, subnet, table)
	filter = updateLinkIndexBasedOnRouteTypes(rtype, subnet, filter)
	existingRoutes, err := util.GetNetLinkOps().RouteListFiltered(netlink.FAMILY_ALL, filter, mask)
	if err != nil {
		return fmt.Errorf("failed to get routes for link %s: %v", link.Attrs().Name, err)
	}
	for _, existingRoute := range existingRoutes {
		if err = util.GetNetLinkOps().RouteDel(&existingRoute); err != nil {
			return err
		}
	}
	return nil
}

// addRouteToStore adds routes to the internal cache
// Must be called with the controller locked
func (c *Controller) addRouteToStore(r netlink.Route) bool {
	existingRoutes, ok := c.store[r.LinkIndex]
	if !ok {
		c.store[r.LinkIndex] = []netlink.Route{r}
		return true
	}
	for _, existingRoute := range existingRoutes {
		if RoutePartiallyEqual(existingRoute, r) {
			return false
		}
	}
	c.store[r.LinkIndex] = append(existingRoutes, r)
	return true
}

// sync will iterate through all routes seen on a node and ensure any route manager managed routes are applied. Any additional
// routes for this link are preserved. sync only inspects routes for links which we managed and ignore routes for non-managed links.
func (c *Controller) sync() {
	c.Lock()
	defer c.Unlock()
	deletedLinkIndexes := make([]int, 0)
	for linkIndex, managedRoutes := range c.store {
		for _, managedRoute := range managedRoutes {
			filterRoute, filterMask := filterRouteByDstAndTable(linkIndex, managedRoute.Dst, managedRoute.Table)
			filterRoute = updateLinkIndexBasedOnRouteTypes(managedRoute.Type, managedRoute.Dst, filterRoute)
			existingRoutes, err := util.GetNetLinkOps().RouteListFiltered(netlink.FAMILY_ALL, filterRoute, filterMask)
			if err != nil {
				klog.Errorf("Route Manager: failed to list routes for link %d with route filter %s and mask filter %d: %v", linkIndex, filterRoute.String(), filterMask, err)
				continue
			}
			var found bool
			for _, activeRoute := range existingRoutes {
				// update link index based on route type and compare
				managedRoute = *updateLinkIndexBasedOnRouteTypes(managedRoute.Type, managedRoute.Dst, &managedRoute)
				if RoutePartiallyEqual(activeRoute, managedRoute) {
					found = true
					break
				}
			}
			if !found {
				link, err := util.GetNetLinkOps().LinkByIndex(managedRoute.LinkIndex)
				if err != nil {
					if util.GetNetLinkOps().IsLinkNotFoundError(err) {
						deletedLinkIndexes = append(deletedLinkIndexes, linkIndex)
					} else {
						klog.Errorf("Route Manager: failed to apply route (%s) because unable to retrieve associated link: %v", managedRoute.String(), err)
					}
					continue
				}
				if err := c.applyRoute(link, managedRoute.Gw, managedRoute.Dst, managedRoute.MTU, managedRoute.Src, managedRoute.Table,
					managedRoute.Priority, managedRoute.Type, managedRoute.Scope); err != nil {
					klog.Errorf("Route Manager: failed to apply route (%s): %v", managedRoute.String(), err)
				}
			}
		}
	}
	for _, linkIndex := range deletedLinkIndexes {
		klog.Infof("Route Manager: removing all routes associated with link index %d because link deleted", linkIndex)
		delete(c.store, linkIndex)
	}
}

func getNetlinkIPFamily(ipNet *net.IPNet) int {
	if utilnet.IsIPv6(ipNet.IP) {
		return netlink.FAMILY_V6
	} else {
		return netlink.FAMILY_V4
	}
}

func filterRouteByDstAndTable(linkIndex int, subnet *net.IPNet, table int) (*netlink.Route, uint64) {
	return &netlink.Route{
			Dst:       subnet,
			LinkIndex: linkIndex,
			Table:     table,
		},
		netlink.RT_FILTER_DST | netlink.RT_FILTER_OIF | netlink.RT_FILTER_TABLE
}

func filterRouteByTable(linkIndex, table int) (*netlink.Route, uint64) {
	return &netlink.Route{
			LinkIndex: linkIndex,
			Table:     table,
		},
		netlink.RT_FILTER_OIF | netlink.RT_FILTER_TABLE
}

func subscribeNetlinkRouteEvents(stopCh <-chan struct{}) (bool, chan netlink.RouteUpdate) {
	routeEventCh := make(chan netlink.RouteUpdate, 20)
	if err := netlink.RouteSubscribe(routeEventCh, stopCh); err != nil {
		klog.Errorf("Route Manager: failed to subscribe to netlink route events: %v", err)
		return false, routeEventCh
	}
	return true, routeEventCh
}

// RoutePartiallyEqual compares a limited set of route attributes.
// The reason for not using the Equal method associated with type netlink.Route is because a user will only specify a limited
// subset of fields but when we introspect routes seen on the system, other fields are populated by default and therefore
// won't be equal anymore with user defined routes. Compare a limited set of fields that we care about.
// Also, netlink.Routes Equal method doesn't compare MTU.
func RoutePartiallyEqual(r, x netlink.Route) bool {
	return r.LinkIndex == x.LinkIndex &&
		util.IsIPNetEqual(r.Dst, x.Dst) &&
		r.Src.Equal(x.Src) &&
		r.Gw.Equal(x.Gw) &&
		r.Table == x.Table &&
		r.Flags == x.Flags &&
		r.MTU == x.MTU
}

// update link index for unreachable or blackhole route based on IP mode. non 0 link index for an
// unreachable or blackhole IPv4 route returns 'invalid argument'. Whereas link index for an unreachable
// or blackhole IPv6 route always get set to 1.
func updateLinkIndexBasedOnRouteTypes(rtype int, subnet *net.IPNet, r *netlink.Route) *netlink.Route {
	if (rtype == unix.RTN_BLACKHOLE || rtype == unix.RTN_UNREACHABLE) && utilnet.IsIPv6(subnet.IP) {
		r.LinkIndex = 1
	} else if (rtype == unix.RTN_BLACKHOLE || rtype == unix.RTN_UNREACHABLE) && !utilnet.IsIPv6(subnet.IP) {
		r.LinkIndex = 0
	}
	return r
}
