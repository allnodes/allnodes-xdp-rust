
use {
    crate::{
        ethtool::{
            self, FLOW_EXT_LEN as EXT_LEN, FLOW_RSS, FLOW_TYPE_FLAGS, RING_MASK, RX_CLS_FLOW_DISC,
            RxFlowSpec, TCPIP4_SPEC_IP4DST as IP4DST, TCPIP4_SPEC_LEN as UNION_LEN,
            TCPIP4_SPEC_PDST as PDST, UDP_V4_FLOW,
        },
        queue_alloc,
    },
    std::{io, net::Ipv4Addr},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RawFlow {
    pub flow_type: u32,
    pub h_u: [u8; UNION_LEN],
    pub h_ext: [u8; EXT_LEN],
    pub m_u: [u8; UNION_LEN],
    pub m_ext: [u8; EXT_LEN],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RuleAction {
    Queue(u32),
    RssContext { id: u32, queues: Vec<u32> },
    Drop,
    Other(u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RuleSpec {
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    pub queue: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InstalledRule {
    pub device: String,
    pub ifindex: u32,
    pub location: u32,
    pub slot: u32,
    pub spec: RuleSpec,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NicRule {
    pub location: u32,
    pub flow: RawFlow,
    pub action: RuleAction,
}

impl RuleSpec {
    pub(crate) fn flow(&self) -> RawFlow {
        let mut h_u = [0u8; UNION_LEN];
        let mut m_u = [0u8; UNION_LEN];
        h_u[IP4DST..IP4DST + 4].copy_from_slice(&self.dst_ip.octets());
        m_u[IP4DST..IP4DST + 4].copy_from_slice(&[0xff; 4]);
        h_u[PDST..PDST + 2].copy_from_slice(&self.dst_port.to_be_bytes());
        m_u[PDST..PDST + 2].copy_from_slice(&[0xff; 2]);
        RawFlow {
            flow_type: UDP_V4_FLOW,
            h_u,
            h_ext: [0; EXT_LEN],
            m_u,
            m_ext: [0; EXT_LEN],
        }
    }
}

impl NicRule {
    pub(crate) fn as_ours(&self) -> Option<RuleSpec> {
        let RuleAction::Queue(queue) = self.action else {
            return None;
        };
        let dst_ip = Ipv4Addr::new(
            self.flow.h_u[IP4DST],
            self.flow.h_u[IP4DST + 1],
            self.flow.h_u[IP4DST + 2],
            self.flow.h_u[IP4DST + 3],
        );
        let dst_port = u16::from_be_bytes([self.flow.h_u[PDST], self.flow.h_u[PDST + 1]]);
        let spec = RuleSpec {
            dst_ip,
            dst_port,
            queue,
        };
        (self.flow == spec.flow()).then_some(spec)
    }

    pub(crate) fn steering_port(&self) -> Option<u16> {
        ethtool::steering_port(&RxFlowSpec {
            flow_type: self.flow.flow_type,
            h_u: self.flow.h_u,
            h_ext: self.flow.h_ext,
            m_u: self.flow.m_u,
            m_ext: self.flow.m_ext,
            ..RxFlowSpec::zeroed()
        })
    }

    pub(crate) fn queues(&self) -> Vec<u32> {
        match &self.action {
            RuleAction::Queue(q) => vec![*q],
            RuleAction::RssContext { queues, .. } => queues.clone(),
            RuleAction::Drop | RuleAction::Other(_) => Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RxChannels {
    pub combined: u32,
    pub rx_only: u32,
}

impl RxChannels {
    pub(crate) const fn total(self) -> u32 {
        self.combined.saturating_add(self.rx_only)
    }
}

pub(crate) trait NicOps {
    fn rx_channels(&self, dev: &str) -> io::Result<RxChannels>;
    fn supports_ntuple(&self, dev: &str) -> io::Result<bool>;
    fn rules(&self, dev: &str) -> io::Result<Vec<NicRule>>;
    fn rss_queues(&self, dev: &str) -> io::Result<Vec<u32>>;
    fn queue_has_xsk(&self, dev: &str, queue: u32) -> io::Result<bool>;
    fn free_location(&self, dev: &str) -> io::Result<u32>;
    fn insert_rule_at(&self, dev: &str, location: u32, spec: &RuleSpec) -> io::Result<()>;
    fn delete_rule(&self, dev: &str, location: u32) -> io::Result<()>;
}

fn decode_rule(
    fs: &RxFlowSpec,
    rss_context: u32,
    table: &dyn Fn(u32) -> io::Result<Vec<u32>>,
) -> io::Result<NicRule> {
    let cookie = fs.ring_cookie;
    let action = if cookie == RX_CLS_FLOW_DISC {
        RuleAction::Drop
    } else if cookie & !RING_MASK != 0 {
        RuleAction::Other(cookie)
    } else if fs.flow_type & FLOW_RSS != 0 {
        let base = u32::try_from(cookie & RING_MASK).map_err(io::Error::other)?;
        let mut queues = Vec::new();
        for entry in table(rss_context)? {
            queues.push(
                entry
                    .checked_add(base)
                    .ok_or_else(|| io::Error::other("queue overflow"))?,
            );
        }
        queues.sort_unstable();
        queues.dedup();
        RuleAction::RssContext {
            id: rss_context,
            queues,
        }
    } else {
        RuleAction::Queue(u32::try_from(cookie).map_err(io::Error::other)?)
    };
    Ok(NicRule {
        location: fs.location,
        flow: RawFlow {
            flow_type: fs.flow_type & !FLOW_TYPE_FLAGS,
            h_u: fs.h_u,
            h_ext: fs.h_ext,
            m_u: fs.m_u,
            m_ext: fs.m_ext,
        },
        action,
    })
}

fn encode_insert(location: u32, spec: &RuleSpec) -> RxFlowSpec {
    let flow = spec.flow();
    RxFlowSpec {
        flow_type: flow.flow_type,
        h_u: flow.h_u,
        m_u: flow.m_u,
        ring_cookie: u64::from(spec.queue),
        location,
        ..RxFlowSpec::zeroed()
    }
}

pub(crate) use crate::queue_alloc::is_busy;

pub(crate) struct EthtoolNic;

impl EthtoolNic {
    fn read_rule(&self, dev: &str, location: u32) -> io::Result<NicRule> {
        let (fs, rss_context) = ethtool::read_rule(dev, location)?;
        decode_rule(&fs, rss_context, &|ctx| ethtool::rss_context_table(dev, ctx))
    }
}

impl NicOps for EthtoolNic {
    fn rx_channels(&self, dev: &str) -> io::Result<RxChannels> {
        let ch = ethtool::get_channels(dev)?;
        Ok(RxChannels {
            combined: ch.combined_count,
            rx_only: ch.rx_count,
        })
    }

    fn supports_ntuple(&self, dev: &str) -> io::Result<bool> {
        ethtool::supports_ntuple(dev)
    }

    fn rules(&self, dev: &str) -> io::Result<Vec<NicRule>> {
        let mut rules = Vec::new();
        for location in ethtool::rule_locations(dev)? {
            let rule = self.read_rule(dev, location).map_err(|e| {
                io::Error::new(e.kind(), format!("rule at location {location}: {e}"))
            })?;
            rules.push(rule);
        }
        Ok(rules)
    }

    fn rss_queues(&self, dev: &str) -> io::Result<Vec<u32>> {
        let mut queues = ethtool::rss_context_table(dev, 0)?;
        queues.sort_unstable();
        queues.dedup();
        Ok(queues)
    }

    fn queue_has_xsk(&self, dev: &str, queue: u32) -> io::Result<bool> {
        queue_alloc::queue_is_free(dev, queue).map(|free| !free)
    }

    fn free_location(&self, dev: &str) -> io::Result<u32> {
        let used = ethtool::rule_locations(dev)?;
        (0u32..)
            .find(|loc| !used.contains(loc))
            .ok_or_else(|| io::Error::other("no free rule location"))
    }

    fn insert_rule_at(&self, dev: &str, location: u32, spec: &RuleSpec) -> io::Result<()> {
        if ethtool::rule_locations(dev)?.contains(&location) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("location {location} is already occupied"),
            ));
        }
        ethtool::insert_rule(dev, encode_insert(location, spec), 0)
    }

    fn delete_rule(&self, dev: &str, location: u32) -> io::Result<()> {
        ethtool::delete_rule(dev, location)
    }
}
