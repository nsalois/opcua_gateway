//! Fixed constructor-only identifier recipes for separately admitted diagnostics.
use crate::{BuildInfo, OpcUaServer, ServerIdentity, TransportLimits};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticIdentifierRecipe {
    MaximumMinusTwo,
    MaximumMinusOne,
    Maximum,
}

impl DiagnosticIdentifierRecipe {
    pub const fn from_recipe(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::MaximumMinusTwo),
            2 => Some(Self::MaximumMinusOne),
            3 => Some(Self::Maximum),
            _ => None,
        }
    }

    pub const fn seed(self) -> u32 {
        match self {
            Self::MaximumMinusTwo => u32::MAX - 2,
            Self::MaximumMinusOne => u32::MAX - 1,
            Self::Maximum => u32::MAX,
        }
    }
}

impl OpcUaServer {
    /// Read-only constructor admission record; not a state setter.
    pub fn diagnostic_initial_identifiers(&self) -> [u32; 4] {
        [
            self.sequence_number,
            self.token_id,
            self.next_session_token_id,
            self.initial_publish_sequence
                .unwrap_or(self.publish_sequence_number),
        ]
    }

    /// Initialize only a new server's volatile owners. No running setter exists.
    /// The Publish recipe is consumed by the first successful subscription,
    /// because normal subscription creation initializes that owner separately.
    pub fn new_with_diagnostic_identifiers(
        identity: ServerIdentity,
        build_info: &'static BuildInfo,
        limits: TransportLimits,
        recipe: DiagnosticIdentifierRecipe,
    ) -> Self {
        let seed = recipe.seed();
        let mut server =
            Self::new_with_limits_and_session_nonce(identity, build_info, limits, seed);
        server.token_id = seed;
        server.sequence_number = seed;
        server.initial_publish_sequence = Some(seed);
        server
    }
}
