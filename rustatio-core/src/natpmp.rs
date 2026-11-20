//! Minimal NAT-PMP (RFC 6886) client used to detect `ProtonVPN`'s forwarded port.
//!
//! `ProtonVPN`'s `WireGuard` virtual adapter exposes a NAT-PMP gateway at a fixed address
//! (`10.2.0.1:5351`). When the official `ProtonVPN` app has Port Forwarding enabled on a
//! P2P server, querying this gateway returns the tunnel's external IPv4 address and the
//! port already forwarded to this session - the same mechanism tools like qbPortWeaver
//! and `natpmpc` use, so it requires no Gluetun or control-server setup.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// `ProtonVPN`'s NAT-PMP gateway address on its `WireGuard` virtual adapter.
pub const PROTONVPN_GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 2, 0, 1);

const NATPMP_PORT: u16 = 5351;
const MAP_LIFETIME_SECS: u32 = 60;

const OP_EXTERNAL_ADDRESS: u8 = 0;
const OP_MAP_TCP: u8 = 2;

const EXTERNAL_ADDRESS_RESPONSE_LEN: usize = 12;
const MAP_PORT_RESPONSE_LEN: usize = 16;

/// Result of a successful NAT-PMP probe against a `ProtonVPN` gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtonVpnStatus {
    /// The tunnel's external (public) IPv4 address.
    pub external_ip: Ipv4Addr,
    /// The TCP port currently forwarded to this session, if Port Forwarding is enabled.
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

/// Probe `gateway` for `ProtonVPN`'s NAT-PMP service.
///
/// Returns `None` when the gateway doesn't respond at all (not connected to a `ProtonVPN`
/// `WireGuard` session, or the service isn't reachable). When the gateway responds,
/// `forwarded_port` is `None` if Port Forwarding isn't enabled for this session, but the
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
    let forwarded_port =
        query_tcp_port_mapping(gateway, request_timeout).await.ok().filter(|port| *port > 0);

    Some(ProtonVpnStatus { external_ip, forwarded_port })
}

async fn send_request(
    gateway: SocketAddrV4,
    request: &[u8],
    request_timeout: Duration,
    min_response_len: usize,
) -> Result<Vec<u8>, NatPmpError> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(gateway).await?;
    socket.send(request).await?;

    let mut buf = vec![0u8; MAP_PORT_RESPONSE_LEN];
    let received = timeout(request_timeout, socket.recv(&mut buf))
        .await
        .map_err(|_| NatPmpError::Timeout)??;

    if received < min_response_len {
        return Err(NatPmpError::Malformed);
    }

    buf.truncate(received);
    Ok(buf)
}

const fn result_code(response: &[u8]) -> u16 {
    u16::from_be_bytes([response[2], response[3]])
}

async fn query_external_address(
    gateway: SocketAddrV4,
    request_timeout: Duration,
) -> Result<Ipv4Addr, NatPmpError> {
    let request = [0u8, OP_EXTERNAL_ADDRESS];
    let response =
        send_request(gateway, &request, request_timeout, EXTERNAL_ADDRESS_RESPONSE_LEN).await?;

    let code = result_code(&response);
    if code != 0 {
        return Err(NatPmpError::ResultCode(code));
    }

    Ok(Ipv4Addr::new(response[8], response[9], response[10], response[11]))
}

async fn query_tcp_port_mapping(
    gateway: SocketAddrV4,
    request_timeout: Duration,
) -> Result<u16, NatPmpError> {
    let mut request = [0u8; 12];
    request[1] = OP_MAP_TCP;
    request[4..6].copy_from_slice(&1u16.to_be_bytes()); // internal port placeholder; Proton's gateway ignores it
    request[6..8].copy_from_slice(&0u16.to_be_bytes()); // suggested external port: any (reads the existing mapping)
    request[8..12].copy_from_slice(&MAP_LIFETIME_SECS.to_be_bytes());

    let response = send_request(gateway, &request, request_timeout, MAP_PORT_RESPONSE_LEN).await?;

    let code = result_code(&response);
    if code != 0 {
        return Err(NatPmpError::ResultCode(code));
    }

    Ok(u16::from_be_bytes([response[10], response[11]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket as TestSocket;

    /// Spawns a fake NAT-PMP responder on loopback and returns its address.
    async fn spawn_fake_gateway(external_ip: Ipv4Addr, mapped_port: u16) -> SocketAddrV4 {
        let socket = TestSocket::bind("127.0.0.1:0").await.expect("bind fake gateway");
        let addr = match socket.local_addr().expect("local addr") {
            std::net::SocketAddr::V4(addr) => addr,
            std::net::SocketAddr::V6(_) => unreachable!("bound to an IPv4 address"),
        };

        tokio::spawn(async move {
            let mut buf = [0u8; 12];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buf).await else { break };
                if len < 2 {
                    continue;
                }

                let mut response = match buf[1] {
                    OP_EXTERNAL_ADDRESS => {
                        let mut resp = vec![0u8; EXTERNAL_ADDRESS_RESPONSE_LEN];
                        resp[1] = 128;
                        resp[8..12].copy_from_slice(&external_ip.octets());
                        resp
                    }
                    OP_MAP_TCP => {
                        let mut resp = vec![0u8; MAP_PORT_RESPONSE_LEN];
                        resp[1] = 128 + OP_MAP_TCP;
                        resp[10..12].copy_from_slice(&mapped_port.to_be_bytes());
                        resp
                    }
                    _ => continue,
                };

                response[0] = 0;
                let _ = socket.send_to(&response, peer).await;
            }
        });

        addr
    }

    #[tokio::test]
    async fn detects_external_ip_and_forwarded_port() {
        let gateway = spawn_fake_gateway(Ipv4Addr::new(185, 1, 2, 3), 54321).await;

        let status = detect_protonvpn_at(gateway, Duration::from_secs(1)).await;

        assert_eq!(
            status,
            Some(ProtonVpnStatus {
                external_ip: Ipv4Addr::new(185, 1, 2, 3),
                forwarded_port: Some(54321),
            })
        );
    }

    #[tokio::test]
    async fn reports_no_forwarded_port_when_mapping_is_zero() {
        let gateway = spawn_fake_gateway(Ipv4Addr::new(10, 20, 30, 40), 0).await;

        let status = detect_protonvpn_at(gateway, Duration::from_secs(1)).await;

        assert_eq!(
            status,
            Some(ProtonVpnStatus {
                external_ip: Ipv4Addr::new(10, 20, 30, 40),
                forwarded_port: None,
            })
        );
    }

    #[tokio::test]
    async fn returns_none_when_gateway_is_unreachable() {
        // Nothing is listening on this loopback port.
        let gateway = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1);

        let status = detect_protonvpn_at(gateway, Duration::from_millis(200)).await;

        assert_eq!(status, None);
    }
}
