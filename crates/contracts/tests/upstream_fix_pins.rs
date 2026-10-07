//! Static pin for an upstream fix absent from the vendored Embassy driver.

const GENERIC_PHY: &str =
    include_str!("../../../vendor/embassy-stm32-0.6.0/src/eth/generic_phy.rs");
const ETH_DRIVER: &str = include_str!("../../../vendor/embassy-stm32-0.6.0/src/eth/mod.rs");

#[test]
#[ignore = "pins open finding BH-14"]
fn ethernet_link_state_is_cached_between_phy_poll_intervals() {
    assert!(
        GENERIC_PHY.contains("fn poll_link(&mut self, cx: &mut Context) -> Option<bool>"),
        "vendored GenericPhy still reports a fresh bool on every driver poll"
    );
    assert!(
        ETH_DRIVER.contains("pub(crate) link_state: LinkState"),
        "vendored Ethernet driver has no cached link-state field"
    );
}
