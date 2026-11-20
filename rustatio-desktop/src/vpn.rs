use std::time::Duration;

use crate::state::AppState;

const POLL_INTERVAL: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// Periodically probes `ProtonVPN`'s NAT-PMP gateway and applies any detected forwarded
/// port to instances with `vpn_port_sync` enabled. Runs for the lifetime of the app -
/// mirrors the existing periodic auto-save task in `main.rs`.
pub async fn run(state: AppState) {
    loop {
        let status =
            rustatio_core::detect_protonvpn(rustatio_core::PROTONVPN_GATEWAY, REQUEST_TIMEOUT)
                .await;

        if let Err(err) = state.apply_vpn_status(status).await {
            log::warn!("Failed to apply ProtonVPN forwarded port: {err}");
        }

        tokio::time::sleep(POLL_INTERVAL).await;
    }
}
