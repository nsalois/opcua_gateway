//! One fixed startup recipe, consumed by the first accepted connection only.
// Firmware policy marker: crate root declares #![no_std]; no alloc or std.
use core::sync::atomic::{AtomicU32, Ordering};
use opta_opcua::{
    BuildInfo, DiagnosticIdentifierRecipe, OpcUaServer, ServerIdentity, TransportLimits,
};

// SAFETY: sole input is consumed at the cache-disabled pre-HAL clock gate.
// The admitted runner may write only recipe0..3 there. Later writes are ignored.
#[unsafe(no_mangle)]
pub static M7_PROTOCOL_RECIPE_INPUT: AtomicU32 = AtomicU32::new(0);
static STARTUP_RECIPE: AtomicU32 = AtomicU32::new(0);

#[repr(C, align(32))]
pub struct Header(pub [AtomicU32; 8]);
// SAFETY: one aligned cache line. The one recipe-winning constructor owns its
// stores; readiness is published last. Debugger observers are read-only.
#[unsafe(no_mangle)]
pub static M7_PROTOCOL_INITIAL_HEADER: Header = Header([const { AtomicU32::new(0) }; 8]);

pub(crate) fn consume_startup_input() {
    let input = M7_PROTOCOL_RECIPE_INPUT.load(Ordering::Relaxed);
    assert!(input <= 3, "identifier recipe must select a fixed seed");
    STARTUP_RECIPE.store(input, Ordering::Release);
}

pub(crate) fn new_server(
    listener: u32,
    identity: ServerIdentity,
    info: &'static BuildInfo,
    nonce: u32,
) -> OpcUaServer {
    let input = STARTUP_RECIPE.swap(0, Ordering::AcqRel);
    let Some(recipe) = DiagnosticIdentifierRecipe::from_recipe(input) else {
        return OpcUaServer::new_with_limits_and_session_nonce(
            identity,
            info,
            TransportLimits::product_target(),
            nonce,
        );
    };
    let server = OpcUaServer::new_with_diagnostic_identifiers(
        identity,
        info,
        TransportLimits::product_target(),
        recipe,
    );
    let [wire, token, session, publish] = server.diagnostic_initial_identifiers();
    for (destination, value) in M7_PROTOCOL_INITIAL_HEADER.0[..7]
        .iter()
        .zip([0x50524f54, input, listener, wire, token, session, publish])
    {
        destination.store(value, Ordering::Relaxed);
    }
    M7_PROTOCOL_INITIAL_HEADER.0[7].store(1, Ordering::Release);
    #[cfg(target_arch = "arm")]
    {
        // SAFETY: this synchronous first constructor is the sole header writer;
        // the exact32-byte cache line contains only this immutable atomic record.
        // Cleaning it does not alter any live owner or stack. Matches the
        // startup diagnostic publication invariant in accelerated_clock.rs.
        let mut cp = unsafe { cortex_m::Peripherals::steal() };
        cp.SCB
            .clean_dcache_by_address(M7_PROTOCOL_INITIAL_HEADER.0.as_ptr() as usize, 32);
    }
    server
}
