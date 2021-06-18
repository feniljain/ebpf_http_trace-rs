#![no_std]
#![no_main]

use redbpf_macros::{map, program, xdp};
use redbpf_probes::xdp::prelude::*;

use ebpf_http_trace::ebpf_http_trace::RequestInfo;

program!(0xFFFFFFFE, "GPL");

#[map("requests")]
static mut REQUESTS: PerfMap<RequestInfo> = PerfMap::with_max_entries(1024);

#[xdp]
pub extern "C" fn trace_http(ctx: XdpContext) -> XdpResult {
    let (ip, transport, data) = match (ctx.ip(), ctx.transport(), ctx.data()) {
        // (Some(ip), Some(t @ Transport::TCP(_)), Some(data)) => (unsafe { *ip }, t, data),
        (Ok(ip), Ok(t @ Transport::TCP(_)), Ok(data)) => (unsafe { *ip }, t, data),
        _ => return Ok(XdpAction::Pass),
    };

    let buff: [u8; 8] = match data.read() {
        Ok(b) => b,
        _ => return Ok(XdpAction::Pass),
    };

    if &buff[..4] != b"GET"
        && &buff[..4] != b"PUT"
        && &buff[..4] != b"PATCH"
        && &buff[..4] != b"DELETE"
        && &buff[..4] != b"POST"
    {
        return Ok(XdpAction::Pass);
    }

    let info = RequestInfo {
        saddr: ip.saddr,
        daddr: ip.daddr,
        sport: transport.source() as u32,
        dport: transport.dest() as u32,
    };

    unsafe {
        REQUESTS.insert(
            &ctx,
            &MapData::with_payload(info, data.offset() as u32, data.len() as u32),
        );
    }

    Ok(XdpAction::Pass)
}

