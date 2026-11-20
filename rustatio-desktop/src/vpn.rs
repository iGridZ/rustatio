use std::time::Duration;

use tauri::AppHandle;

use crate::logging::log_and_emit;
use crate::state::AppState;

const POLL_INTERVAL: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// Periodically probes `ProtonVPN`'s NAT-PMP gateway and its log for the forwarded port,
/// applying any change to instances with `vpn_port_sync` enabled. Runs for the lifetime
/// of the app - mirrors the existing periodic auto-save task in `main.rs`. Logs (visibly,
/// in the app's own log panel) whenever the detected port or a log-read failure changes,
/// so detection problems are diagnosable without a debugger.
pub async fn run(app: AppHandle, state: AppState) {
    let mut last_forwarded_port: Option<u16> = None;
    let mut last_log_error: Option<String> = None;

    loop {
        let status =
            rustatio_core::detect_protonvpn(rustatio_core::PROTONVPN_GATEWAY, REQUEST_TIMEOUT)
                .await;

        match rustatio_core::read_forwarded_port_from_log() {
            Ok(port) => {
                if last_log_error.take().is_some() {
                    log_and_emit!(&app, info, "ProtonVPN forwarded-port log is readable again");
                }
                if port != last_forwarded_port {
                    last_forwarded_port = port;
                    match port {
                        Some(p) => {
                            log_and_emit!(&app, info, "ProtonVPN forwarded port detected: {p}");
                        }
                        None => {
                            log_and_emit!(
                                &app,
                                info,
                                "ProtonVPN log found no active port forwarding mapping"
                            );
                        }
                    }
                }
            }
            Err(err) => {
                if last_log_error.as_deref() != Some(err.as_str()) {
                    last_log_error = Some(err.clone());
                    log_and_emit!(&app, warn, "Could not read ProtonVPN's forwarded-port log: {err}");
                }
            }
        }

        if let Err(err) = state.apply_vpn_status(status).await {
            log_and_emit!(&app, warn, "Failed to apply ProtonVPN forwarded port: {err}");
        }

        tokio::time::sleep(POLL_INTERVAL).await;
    }
}
