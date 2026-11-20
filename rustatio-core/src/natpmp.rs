//! Detects `ProtonVPN`'s tunnel IP and forwarded port.
//!
//! `ProtonVPN`'s `WireGuard` virtual adapter exposes a NAT-PMP gateway at a fixed address
//! (`10.2.0.1:5351`), which this module queries (RFC 6886 "External Address" request) for
//! the tunnel's external IPv4 address. Port forwarding itself, however, is read from the
//! official `ProtonVPN` app's own log file rather than requested over NAT-PMP: each NAT-PMP
//! client gets an independent mapping, so a NAT-PMP request from this app would allocate a
//! brand-new port unrelated to the one the `ProtonVPN` app negotiated and is displaying.
//! Reading its log (the same source qbPortWeaver's default "Log File Parsing" mode uses)
//! reports the port that is actually in effect.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// `ProtonVPN`'s NAT-PMP gateway address on its `WireGuard` virtual adapter.
pub const PROTONVPN_GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 2, 0, 1);

const NATPMP_PORT: u16 = 5351;
const OP_EXTERNAL_ADDRESS: u8 = 0;
const EXTERNAL_ADDRESS_RESPONSE_LEN: usize = 12;

/// Result of a successful `ProtonVPN` detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtonVpnStatus {
    /// The tunnel's external (public) IPv4 address.
    pub external_ip: Ipv4Addr,
    /// The port `ProtonVPN`'s own app currently has forwarded, if Port Forwarding is
    /// enabled. The same number is used for both TCP and UDP.
    pub forwarded_port: Option<u16>,
}

#[derive(Debug, Error)]
enum NatPmpError {
    #[error("NAT-PMP request timed out")]
    Timeout,
    #[error("NAT-PMP I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed NAT-PMP response")]
    Malformed,
    #[error("NAT-PMP gateway returned result code {0}")]
    ResultCode(u16),
}

/// Probe `gateway` for `ProtonVPN`'s NAT-PMP service and read its forwarded port.
///
/// Returns `None` when the gateway doesn't respond at all (not connected to a `ProtonVPN`
/// `WireGuard` session, or the service isn't reachable). When the gateway responds,
/// `forwarded_port` is `None` if the app's log doesn't show an active mapping, but the
/// external IP is still returned.
pub async fn detect_protonvpn(
    gateway: Ipv4Addr,
    request_timeout: Duration,
) -> Option<ProtonVpnStatus> {
    detect_protonvpn_at(SocketAddrV4::new(gateway, NATPMP_PORT), request_timeout).await
}

async fn detect_protonvpn_at(
    gateway: SocketAddrV4,
    request_timeout: Duration,
) -> Option<ProtonVpnStatus> {
    let external_ip = query_external_address(gateway, request_timeout).await.ok()?;
    let forwarded_port = read_forwarded_port_from_log();

    Some(ProtonVpnStatus { external_ip, forwarded_port })
}

async fn query_external_address(
    gateway: SocketAddrV4,
    request_timeout: Duration,
) -> Result<Ipv4Addr, NatPmpError> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(gateway).await?;
    socket.send(&[0u8, OP_EXTERNAL_ADDRESS]).await?;

    let mut buf = [0u8; EXTERNAL_ADDRESS_RESPONSE_LEN];
    let received = timeout(request_timeout, socket.recv(&mut buf))
        .await
        .map_err(|_| NatPmpError::Timeout)??;

    if received < EXTERNAL_ADDRESS_RESPONSE_LEN {
        return Err(NatPmpError::Malformed);
    }

    let result_code = u16::from_be_bytes([buf[2], buf[3]]);
    if result_code != 0 {
        return Err(NatPmpError::ResultCode(result_code));
    }

    Ok(Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]))
}

/// Reads the most recent forwarded port the `ProtonVPN` app logged for this session.
///
/// `ProtonVPN` logs lines like:
/// `... Received PortForwarding Status 'SleepingUntilRefresh' ..., Port pair 47055->47055, ...`
fn read_forwarded_port_from_log() -> Option<u16> {
    let log_path =
        dirs::data_local_dir()?.join("Proton").join("ProtonVPN").join("Logs").join("client-logs.txt");
    let content = std::fs::read_to_string(log_path).ok()?;
    content.lines().rev().find_map(parse_port_pair_line)
}

fn parse_port_pair_line(line: &str) -> Option<u16> {
    let after_marker = line.split_once("Port pair ")?.1;
    let pair = after_marker.split(',').next()?;
    let (_, external) = pair.split_once("->")?;
    external.trim().parse::<u16>().ok().filter(|port| *port > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket as TestSocket;

    /// Spawns a fake NAT-PMP responder on loopback answering only the External Address
    /// request, and returns its address.
    async fn spawn_fake_gateway(external_ip: Ipv4Addr) -> SocketAddrV4 {
        let socket = TestSocket::bind("127.0.0.1:0").await.expect("bind fake gateway");
        let addr = match socket.local_addr().expect("local addr") {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => unreachable!("bound to an IPv4 address"),
        };

        tokio::spawn(async move {
            let mut buf = [0u8; 12];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buf).await else { break };
                if len < 2 || buf[1] != OP_EXTERNAL_ADDRESS {
                    continue;
                }

                let mut response = vec![0u8; EXTERNAL_ADDRESS_RESPONSE_LEN];
                response[1] = 128;
                response[8..12].copy_from_slice(&external_ip.octets());
                let _ = socket.send_to(&response, peer).await;
            }
        });

        addr
    }

    #[tokio::test]
    async fn detects_external_ip_from_gateway() {
        let gateway = spawn_fake_gateway(Ipv4Addr::new(185, 1, 2, 3)).await;

        let status = detect_protonvpn_at(gateway, Duration::from_secs(1)).await;

        assert_eq!(status.map(|s| s.external_ip), Some(Ipv4Addr::new(185, 1, 2, 3)));
    }

    #[tokio::test]
    async fn returns_none_when_gateway_is_unreachable() {
        // Nothing is listening on this loopback port.
        let gateway = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1);

        let status = detect_protonvpn_at(gateway, Duration::from_millis(200)).await;

        assert_eq!(status, None);
    }

    #[test]
    fn parses_the_real_protonvpn_log_line_format() {
        let line = "2026-11-20T14:33:54.091Z | INFO  | PROCESS.COMM | Received PortForwarding Status 'SleepingUntilRefresh' triggered at '20/11/2026 2:33:54', Port pair 47055->47055, expiring in 00:01:00 at 20/11/2026 2:34:54";

        assert_eq!(parse_port_pair_line(line), Some(47055));
    }

    #[test]
    fn parse_port_pair_line_ignores_unrelated_lines() {
        assert_eq!(parse_port_pair_line("2026-11-20T14:33:54.091Z | INFO | something else"), None);
    }

    #[test]
    fn parse_port_pair_line_rejects_a_zero_port() {
        let line = "... Port pair 0->0, expiring in 00:01:00 ...";

        assert_eq!(parse_port_pair_line(line), None);
    }

    #[test]
    fn read_forwarded_port_from_log_takes_the_most_recent_matching_line() {
        let log = "\
line one, Port pair 11111->11111, expiring in 00:01:00
line two, no port here
line three, Port pair 47055->47055, expiring in 00:01:00";

        let last_match = log.lines().rev().find_map(parse_port_pair_line);
        assert_eq!(last_match, Some(47055));
    }
}
