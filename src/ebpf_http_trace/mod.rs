// use cty::*;
pub use redbpf_probes::xdp::MapData;

#[derive(Debug)]
pub struct RequestInfo {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u32,
    pub dport: u32,
}
