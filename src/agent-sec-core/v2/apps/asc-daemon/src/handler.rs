use asc_daemon_core::{PeerCredentials, PolicyAdministration};
use asc_daemon_protocol::method::{self, MethodId};
use asc_daemon_protocol::{DaemonRequest, DaemonResponse, RequestId, error_code};

use crate::pap_handler::PapHandler;

/// Method router composed over daemon application handlers.
pub struct DaemonHandler {
    pap: PapHandler,
}

impl DaemonHandler {
    /// Composes the protocol adapter from Policy administration use cases.
    pub fn new(application: impl PolicyAdministration + 'static) -> Self {
        Self {
            pap: PapHandler::new(application),
        }
    }

    /// Handles one decoded request using transport-authenticated peer identity.
    pub fn handle(
        &self,
        request_id: RequestId,
        peer: PeerCredentials,
        request: DaemonRequest,
    ) -> DaemonResponse {
        let Some(method_id) = method::resolve(&request.method) else {
            return DaemonResponse::error(
                request_id,
                error_code::UNKNOWN_METHOD,
                "daemon method is not implemented",
            );
        };

        let MethodId::Pap(method) = method_id;
        self.pap.handle(request_id, peer, method, request.params)
    }
}
