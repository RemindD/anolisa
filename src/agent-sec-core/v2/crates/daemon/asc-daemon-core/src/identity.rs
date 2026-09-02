/// Kernel-authenticated identity of the process connected to the daemon.
///
/// The protocol must never deserialize this type from request content. A
/// trusted transport adapter constructs it from peer credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    uid: u32,
    gid: u32,
    pid: u32,
}

impl PeerCredentials {
    /// Creates a trusted peer identity from transport-owned credentials.
    pub const fn new(uid: u32, gid: u32, pid: u32) -> Self {
        Self { uid, gid, pid }
    }

    /// Returns the authenticated user identity.
    pub const fn uid(self) -> u32 {
        self.uid
    }

    /// Returns the authenticated group identity.
    pub const fn gid(self) -> u32 {
        self.gid
    }

    /// Returns the authenticated process identity.
    pub const fn pid(self) -> u32 {
        self.pid
    }
}

/// Server-assigned authorization role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalRole {
    /// Authenticated local caller without Policy administration authority.
    LocalUser,
    /// Authenticated caller allowed to administer Policy and Scope resources.
    PolicyAdministrator,
}

/// Trusted daemon principal derived from peer credentials and server policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Principal {
    peer: PeerCredentials,
    role: PrincipalRole,
}

impl Principal {
    /// Creates a principal after a trusted adapter authenticates the peer.
    ///
    /// This constructor must not receive a role copied from request content.
    pub const fn from_authenticated_peer(peer: PeerCredentials, role: PrincipalRole) -> Self {
        Self { peer, role }
    }

    /// Returns the kernel-authenticated peer identity.
    pub const fn peer(self) -> PeerCredentials {
        self.peer
    }

    /// Returns the server-assigned role.
    pub const fn role(self) -> PrincipalRole {
        self.role
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_keeps_transport_identity_separate_from_server_role() {
        let peer = PeerCredentials::new(1000, 100, 4242);
        let principal =
            Principal::from_authenticated_peer(peer, PrincipalRole::PolicyAdministrator);

        assert_eq!(principal.peer().uid(), 1000);
        assert_eq!(principal.peer().gid(), 100);
        assert_eq!(principal.peer().pid(), 4242);
        assert_eq!(principal.role(), PrincipalRole::PolicyAdministrator);
    }
}
