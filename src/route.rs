// Derived from Agave's `xdp` crate (https://github.com/anza-xyz/agave, Apache-2.0);
// changed by Allnodes. See NOTICE.
use {
    crate::{
        lpm::Ipv4Lpm,
        netlink::{
            GreTunnelInfo, InterfaceInfo, MacAddress, NeighborEntry, RouteEntry,
            netlink_get_interfaces, netlink_get_neighbors, netlink_get_routes,
        },
    },
    libc::{AF_INET, RT_TABLE_DEFAULT, RT_TABLE_LOCAL, RT_TABLE_MAIN},
    std::{
        cmp::Ordering,
        fmt, io,
        net::{IpAddr, Ipv4Addr},
    },
    thiserror::Error,
};

#[derive(Debug, Error)]
pub enum RouteError {
    #[error("no route found to destination {0}")]
    NoRouteFound(IpAddr),

    #[error("missing output interface in route")]
    MissingOutputInterface,

    #[error("could not resolve MAC address")]
    MacResolutionError,

    #[error("unknown interface index {0}")]
    UnknownInterfaceIndex(u32),
}

#[derive(Debug, Clone)]
pub struct GreRouteInfo {
    pub if_index: u32,
    pub mtu: u32,
    pub underlay_mtu: u32,
    pub tunnel_info: GreTunnelInfo,
    pub underlay_if_index: u32,
    pub underlay_ip_addr: Ipv4Addr,
    pub underlay_mac_addr: Option<MacAddress>,
    pub underlay_neigh_requires_refresh: bool,
}

/// VLAN encapsulation directive carried on a resolved NextHop.
///
/// When present, the tx loop prepends an 802.1Q tag to the Ethernet header before the inner IP
/// header. The MAC and IP fields on the NextHop are still the real packet destinations: VLAN
/// encapsulation changes the L2 framing only. XDP cannot transmit on a VLAN sub-interface
/// directly (it is bound to the physical parent), so the tag has to be written in userspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlanRouteInfo {
    /// if_index of the VLAN sub-interface the route resolved to.
    pub if_index: u32,
    pub vid: u16,
    /// Priority Code Point. Always 0 for now, matching the kernel's default egress QoS mapping;
    /// a configurable mapping can be added later if needed.
    pub pcp: u8,
}

#[derive(Debug, Clone)]
pub struct NextHop {
    pub mac_addr: Option<MacAddress>,
    pub ip_addr: IpAddr,
    pub if_index: u32,
    pub mtu: u32,
    pub neigh_requires_refresh: bool,
    pub preferred_src_ip: Option<Ipv4Addr>,
    pub gre: Option<GreRouteInfo>,
    pub vlan: Option<VlanRouteInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteTable {
    Default,
    Local,
    Main,
    Other(u32),
}

impl std::fmt::Display for RouteTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Default => f.write_str("default"),
            Self::Local => f.write_str("local"),
            Self::Main => f.write_str("main"),
            Self::Other(table) => write!(f, "{table}"),
        }
    }
}

impl From<RouteTable> for u32 {
    fn from(table: RouteTable) -> Self {
        match table {
            RouteTable::Default => u32::from(RT_TABLE_DEFAULT),
            RouteTable::Local => u32::from(RT_TABLE_LOCAL),
            RouteTable::Main => u32::from(RT_TABLE_MAIN),
            RouteTable::Other(table) => table,
        }
    }
}

impl From<u32> for RouteTable {
    fn from(table: u32) -> Self {
        match table {
            table if table == u32::from(RT_TABLE_DEFAULT) => Self::Default,
            table if table == u32::from(RT_TABLE_LOCAL) => Self::Local,
            table if table == u32::from(RT_TABLE_MAIN) => Self::Main,
            table => Self::Other(table),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route<T> {
    pub destination: Option<T>,
    pub gateway: Option<T>,
    pub preferred_src: Option<T>,
    pub out_if_index: Option<u32>,
    pub priority: Option<u32>,
    pub type_: u8,
    pub dst_len: u8,
}

impl<T: PartialEq> Route<T> {
    fn same_key(&self, other: &Self) -> bool {
        self.destination == other.destination
            && self.dst_len == other.dst_len
            && self.priority == other.priority
            && self.type_ == other.type_
    }
}

impl TryFrom<RouteEntry> for Route<Ipv4Addr> {
    type Error = ();

    fn try_from(entry: RouteEntry) -> Result<Self, Self::Error> {
        if entry.family != AF_INET as u8 {
            return Err(());
        }

        let destination = match entry.destination {
            Some(IpAddr::V4(addr)) => Some(addr),
            Some(IpAddr::V6(_)) => return Err(()),
            None => None,
        };
        let gateway = match entry.gateway {
            Some(IpAddr::V4(addr)) => Some(addr),
            Some(IpAddr::V6(_)) => return Err(()),
            None => None,
        };
        let preferred_src = match entry.pref_src {
            Some(IpAddr::V4(addr)) => Some(addr),
            Some(IpAddr::V6(_)) => return Err(()),
            None => None,
        };
        let out_if_index = entry
            .out_if_index
            .map(u32::try_from)
            .transpose()
            .map_err(|_| ())?;

        Ok(Self {
            destination,
            gateway,
            preferred_src,
            out_if_index,
            priority: entry.priority,
            type_: entry.type_,
            dst_len: entry.dst_len.min(32),
        })
    }
}

#[derive(Clone, Debug)]
pub struct Interfaces {
    interfaces: Vec<InterfaceInfo>,
}

impl Interfaces {
    pub fn new(interfaces: Vec<InterfaceInfo>) -> Self {
        Self { interfaces }
    }

    pub fn from_netlink() -> Result<Self, io::Error> {
        Ok(Self::new(netlink_get_interfaces(AF_INET as u8)?))
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &InterfaceInfo> {
        self.interfaces.iter()
    }

    fn upsert(&mut self, new_interface: InterfaceInfo) -> bool {
        if let Some(existing) = self
            .interfaces
            .iter_mut()
            .find(|old| old.if_index == new_interface.if_index)
        {
            if existing != &new_interface {
                *existing = new_interface;
                return true;
            }
            return false;
        }
        self.interfaces.push(new_interface);
        true
    }

    fn remove(&mut self, if_index: u32) -> bool {
        if let Some(i) = self
            .interfaces
            .iter()
            .position(|old| old.if_index == if_index)
        {
            self.interfaces.swap_remove(i);
            return true;
        }
        false
    }
}

#[derive(Clone)]
pub struct Neighbors {
    neighbors: Vec<NeighborEntry>,
}

impl Neighbors {
    pub fn new(neighbors: Vec<NeighborEntry>) -> Self {
        Self { neighbors }
    }

    pub fn from_netlink() -> Result<Self, io::Error> {
        Ok(Self::new(netlink_get_neighbors(None, AF_INET as u8)?))
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &NeighborEntry> {
        self.neighbors.iter()
    }

    fn lookup(&self, ip: IpAddr, if_index: u32) -> Option<&NeighborEntry> {
        self.neighbors
            .iter()
            .find(|n| n.ifindex == if_index as i32 && n.destination == Some(ip))
    }

    fn upsert(&mut self, new_neighbor: NeighborEntry) -> bool {
        let Some((ifidx, ip)) = new_neighbor.key() else {
            return false;
        };

        if let Some(i) = self
            .neighbors
            .iter()
            .position(|old| old.ifindex == ifidx && old.destination == Some(IpAddr::V4(ip)))
        {
            if self.neighbors[i] != new_neighbor {
                self.neighbors[i] = new_neighbor;
                return true;
            }
            false
        } else {
            self.neighbors.push(new_neighbor);
            true
        }
    }

    fn remove(&mut self, ip: Ipv4Addr, if_index: u32) -> bool {
        if let Some(i) = self.neighbors.iter().position(|old| {
            old.ifindex == if_index as i32 && old.destination == Some(IpAddr::V4(ip))
        }) {
            self.neighbors.swap_remove(i);
            return true;
        }
        false
    }
}

#[derive(Clone)]
pub struct Routes {
    pub(crate) table: RouteTable,
    routes: Vec<Route<Ipv4Addr>>,
}

impl Routes {
    pub fn new(table: RouteTable, mut routes: Vec<Route<Ipv4Addr>>) -> Self {
        routes.sort_by(Self::compare_routes);
        Self { table, routes }
    }

    pub fn from_netlink(table: RouteTable) -> Result<Self, io::Error> {
        let routes = netlink_get_routes(AF_INET as u8, u32::from(table))?
            .into_iter()
            .filter_map(|entry| Route::try_from(entry).ok())
            .collect();
        Ok(Self::new(table, routes))
    }

    fn compare_routes(left: &Route<Ipv4Addr>, right: &Route<Ipv4Addr>) -> Ordering {
        right
            .dst_len
            .cmp(&left.dst_len)
            .then_with(|| left.priority.unwrap_or(0).cmp(&right.priority.unwrap_or(0)))
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Route<Ipv4Addr>> {
        self.routes.iter()
    }

    fn get(&self, route_idx: usize) -> Option<&Route<Ipv4Addr>> {
        self.routes.get(route_idx)
    }

    fn as_slice(&self) -> &[Route<Ipv4Addr>] {
        &self.routes
    }

    fn upsert(&mut self, new_route: RouteEntry) -> bool {
        if !new_route
            .table
            .is_some_and(|table| self.table == RouteTable::from(table))
        {
            return false;
        }

        let Ok(new_route) = Route::try_from(new_route) else {
            return false;
        };

        if let Some(existing) = self.routes.iter_mut().find(|old| old.same_key(&new_route)) {
            if existing != &new_route {
                *existing = new_route;
                return true;
            }
            false
        } else {
            let route = new_route;
            let insert_at = self.routes.partition_point(|existing| {
                matches!(
                    Self::compare_routes(existing, &route),
                    Ordering::Less | Ordering::Equal
                )
            });
            self.routes.insert(insert_at, route);
            true
        }
    }

    fn remove(&mut self, new_route: RouteEntry) -> bool {
        if !new_route
            .table
            .is_some_and(|table| self.table == RouteTable::from(table))
        {
            return false;
        }

        let Ok(new_route) = Route::try_from(new_route) else {
            return false;
        };

        if let Some(i) = self.routes.iter().position(|old| old.same_key(&new_route)) {
            self.routes.remove(i);
            true
        } else {
            false
        }
    }
}

#[derive(Clone)]
pub struct RoutingTables {
    pub(crate) routes: Routes,
    neighbors: Neighbors,
    interfaces: Interfaces,
}

impl RoutingTables {
    pub fn new(routes: Routes, neighbors: Neighbors, interfaces: Interfaces) -> Self {
        Self {
            routes,
            neighbors,
            interfaces,
        }
    }

    pub fn from_netlink(table: RouteTable) -> Result<Self, io::Error> {
        Ok(Self::new(
            Routes::from_netlink(table)?,
            Neighbors::from_netlink()?,
            Interfaces::from_netlink()?,
        ))
    }

    pub fn upsert_route(&mut self, new_route: RouteEntry) -> bool {
        self.routes.upsert(new_route)
    }

    pub fn remove_route(&mut self, new_route: RouteEntry) -> bool {
        self.routes.remove(new_route)
    }

    pub fn upsert_neighbor(&mut self, new_neighbor: NeighborEntry) -> bool {
        self.neighbors.upsert(new_neighbor)
    }

    pub fn remove_neighbor(&mut self, ip: Ipv4Addr, if_index: u32) -> bool {
        self.neighbors.remove(ip, if_index)
    }

    pub fn upsert_interface(&mut self, new_interface: InterfaceInfo) -> bool {
        self.interfaces.upsert(new_interface)
    }

    pub fn remove_interface(&mut self, if_index: u32) -> bool {
        self.interfaces.remove(if_index)
    }
}

#[derive(Clone)]
pub struct Router {
    neighbors: Neighbors,
    routes: Routes,
    ipv4_lpm: Ipv4Lpm,
    interfaces: Interfaces,
    // cache for the default route next hop so we can avoid arp table lookups on the common case
    cached_default_route: Option<NextHop>,
    // cache for gre route info keyed by interface index. This stays tiny in practice.
    cached_gre_info: Vec<GreRouteInfo>,
    // cache for vlan encap info keyed by interface index. One entry per VLAN sub-interface.
    cached_vlan_info: Vec<VlanRouteInfo>,
    unusable_gre: Vec<(u32, &'static str)>,
}

struct RoutingTableDisplay<'a>(&'a [Route<Ipv4Addr>]);

impl fmt::Display for RoutingTableDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("<empty>");
        }

        for (i, route) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("\n")?;
            }
            format_route(f, route)?;
        }

        Ok(())
    }
}

impl Router {
    pub fn new() -> Result<Self, io::Error> {
        Self::from_tables(RoutingTables::from_netlink(RouteTable::Main)?)
    }

    pub fn from_tables(tables: RoutingTables) -> Result<Self, io::Error> {
        let ipv4_lpm = Ipv4Lpm::build(tables.routes.as_slice());
        let mut router = Self {
            neighbors: tables.neighbors,
            routes: tables.routes,
            ipv4_lpm,
            interfaces: tables.interfaces,
            cached_default_route: None,
            cached_gre_info: Vec::new(),
            cached_vlan_info: Vec::new(),
            unusable_gre: Vec::new(),
        };

        for interface in router.interfaces.iter() {
            if interface.gre_tunnel.is_some() {
                match router.interface_gre_route_info(interface) {
                    Ok(gre) => router.cached_gre_info.push(gre),
                    Err(Some(reason)) => router.unusable_gre.push((interface.if_index, reason)),
                    Err(None) => {}
                }
            }
            if let Some(vlan) = interface.vlan_link {
                router.cached_vlan_info.push(VlanRouteInfo {
                    if_index: interface.if_index,
                    vid: vlan.vid,
                    // Kernel default egress QoS mapping; a configurable mapping can come later.
                    pcp: 0,
                });
            }
        }

        router.cached_default_route = match router.default_route() {
            Ok(hop) => Some(hop),
            Err(RouteError::NoRouteFound(_)) => None,
            Err(e) => return Err(io::Error::other(e)),
        };

        Ok(router)
    }

    pub fn routing_table(&self) -> impl fmt::Display + '_ {
        RoutingTableDisplay(self.routes.as_slice())
    }

    fn cached_gre_route_info(&self, if_index: u32) -> Option<&GreRouteInfo> {
        self.cached_gre_info
            .iter()
            .find(|gre| gre.if_index == if_index)
    }

    fn gre_route_info(&self, if_index: u32) -> Option<GreRouteInfo> {
        self.cached_gre_route_info(if_index).cloned()
    }

    pub fn unusable_gre(&self) -> &[(u32, &'static str)] {
        &self.unusable_gre
    }

    fn cached_vlan_route_info(&self, if_index: u32) -> Option<VlanRouteInfo> {
        self.cached_vlan_info
            .iter()
            .find(|vlan| vlan.if_index == if_index)
            .copied()
    }

    fn resolve_next_hop(
        &self,
        route_ip: Ipv4Addr,
        route: &Route<Ipv4Addr>,
    ) -> Result<NextHop, RouteError> {
        let if_index = route
            .out_if_index
            .ok_or(RouteError::MissingOutputInterface)?;
        let next_hop_v4 = route.gateway.unwrap_or(route_ip);
        let next_hop_ip = IpAddr::V4(next_hop_v4);
        let preferred_src_ip = route.preferred_src;

        if let Some(default_route) = &self.cached_default_route
            && default_route.ip_addr == next_hop_ip
            && default_route.if_index == if_index
        {
            return Ok(NextHop {
                ip_addr: next_hop_ip,
                if_index,
                mtu: default_route.mtu,
                mac_addr: default_route.mac_addr,
                neigh_requires_refresh: default_route.neigh_requires_refresh,
                preferred_src_ip,
                gre: default_route.gre.clone(),
                vlan: default_route.vlan,
            });
        }

        if let Some(gre) = self.gre_route_info(if_index) {
            return Ok(NextHop {
                if_index,
                mtu: gre.underlay_mtu,
                ip_addr: next_hop_ip,
                mac_addr: gre.underlay_mac_addr,
                neigh_requires_refresh: gre.underlay_neigh_requires_refresh,
                preferred_src_ip,
                gre: Some(gre),
                vlan: None,
            });
        }

        let mtu = self
            .interfaces
            .iter()
            .find(|interface| interface.if_index == if_index)
            .map(|interface| interface.mtu)
            .ok_or(RouteError::UnknownInterfaceIndex(if_index))?;
        let vlan = self.cached_vlan_route_info(if_index);

        // IPv4 multicast destinations map deterministically to a multicast MAC (RFC 1112 §6.4)
        // and never participate in ARP, so there is no neighbor entry to look up. Otherwise
        // consult the neighbor cache for the unicast MAC.
        let (mac_addr, neigh_requires_refresh) = if next_hop_v4.is_multicast() {
            (Some(ipv4_multicast_mac(next_hop_v4)), false)
        } else {
            let neighbor = self.neighbors.lookup(next_hop_ip, if_index);
            (
                neighbor.and_then(|neighbor| neighbor.lladdr),
                neighbor.is_none_or(NeighborEntry::requires_refresh),
            )
        };
        Ok(NextHop {
            ip_addr: next_hop_ip,
            mac_addr,
            if_index,
            mtu,
            neigh_requires_refresh,
            preferred_src_ip,
            gre: None,
            vlan,
        })
    }

    fn default_route(&self) -> Result<NextHop, RouteError> {
        let default_route = self
            .ipv4_lpm
            .default_route()
            .and_then(|route_idx| self.routes.get(route_idx as usize))
            .ok_or(RouteError::NoRouteFound(IpAddr::V4(Ipv4Addr::UNSPECIFIED)))?;
        self.resolve_next_hop(Ipv4Addr::UNSPECIFIED, default_route)
    }

    pub fn default(&self) -> Result<NextHop, RouteError> {
        if let Some(default_route) = &self.cached_default_route {
            Ok(default_route.clone())
        } else {
            self.default_route()
        }
    }

    #[inline]
    pub fn lookup_route_v4(&self, dest_ip: Ipv4Addr) -> Option<&Route<Ipv4Addr>> {
        self.ipv4_lpm
            .lookup(dest_ip)
            .and_then(|route_idx| self.routes.get(route_idx as usize))
    }

    #[inline]
    pub fn route_v4(&self, dest_ip: Ipv4Addr) -> Result<NextHop, RouteError> {
        let route = self
            .lookup_route_v4(dest_ip)
            .ok_or(RouteError::NoRouteFound(dest_ip.into()))?;
        self.resolve_next_hop(dest_ip, route)
    }

    fn interface_gre_route_info(
        &self,
        interface: &InterfaceInfo,
    ) -> Result<GreRouteInfo, Option<&'static str>> {
        let tunnel_info = interface.gre_tunnel.as_ref().ok_or(None)?;
        let remote = match tunnel_info.remote {
            IpAddr::V4(remote) => remote,
            IpAddr::V6(_) => return Err(None),
        };
        let local = match tunnel_info.local {
            IpAddr::V4(local) => local,
            IpAddr::V6(_) => return Err(None),
        };
        if remote == Ipv4Addr::UNSPECIFIED {
            return Err(None);
        }
        if local == Ipv4Addr::UNSPECIFIED {
            return Err(Some("no local address"));
        }

        let underlay_route = self
            .lookup_route_v4(remote)
            .ok_or(Some("no route to the remote"))?;
        let underlay_if_index = underlay_route
            .out_if_index
            .ok_or(Some("remote route has no output interface"))?;
        let underlay_interface = self
            .interfaces
            .iter()
            .find(|candidate| candidate.if_index == underlay_if_index)
            .ok_or(Some("underlay interface unknown"))?;
        if underlay_interface.is_gre() {
            return Err(Some("gre over gre"));
        }
        let underlay_ip_addr = underlay_route.gateway.unwrap_or(remote);
        let underlay_neighbor = self
            .neighbors
            .lookup(IpAddr::V4(underlay_ip_addr), underlay_if_index);
        let underlay_mac_addr = underlay_neighbor.and_then(|neighbor| neighbor.lladdr);

        Ok(GreRouteInfo {
            if_index: interface.if_index,
            mtu: interface.mtu,
            underlay_mtu: underlay_interface.mtu,
            tunnel_info: tunnel_info.clone(),
            underlay_if_index,
            underlay_ip_addr,
            underlay_mac_addr,
            underlay_neigh_requires_refresh: underlay_neighbor
                .is_none_or(NeighborEntry::requires_refresh),
        })
    }
}

/// Map an IPv4 multicast address to its Ethernet destination MAC per RFC 1112 §6.4:
/// the low 23 bits of the address are placed into the low 23 bits of `01:00:5e:00:00:00`.
#[inline]
fn ipv4_multicast_mac(ip: Ipv4Addr) -> MacAddress {
    let [_, b1, b2, b3] = ip.octets();
    MacAddress([0x01, 0x00, 0x5e, b1 & 0x7f, b2, b3])
}

fn format_route(f: &mut fmt::Formatter<'_>, route: &Route<Ipv4Addr>) -> fmt::Result {
    match route.destination {
        Some(destination) if route.dst_len == 32 => write!(f, "{destination}")?,
        Some(destination) => write!(f, "{destination}/{}", route.dst_len)?,
        None => f.write_str("default")?,
    }

    if let Some(gateway) = route.gateway {
        write!(f, " via {gateway}")?;
    }
    if let Some(if_index) = route.out_if_index {
        write!(f, " dev if{if_index}")?;
    }
    if let Some(preferred_src) = route.preferred_src {
        write!(f, " src {preferred_src}")?;
    }
    if let Some(priority) = route.priority {
        write!(f, " metric {priority}")?;
    }

    Ok(())
}
