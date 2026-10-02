// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
use core::sync::atomic::Ordering;
use core::task::Context;

use embassy_stm32::eth::{GenericPhy, Phy, StationManagement};

#[cfg(feature = "product")]
use crate::probes::{
    M7_ETH_PHY_ANLPAR_SNAPSHOT, M7_ETH_PHY_PHYSCSR_SNAPSHOT, M7_ETH_PHY_SECR_RAW_SNAPSHOT,
};

const LAN8742_PHY_ADDR: u8 = 0;
const LAN8742_REG_ANLPAR: u8 = 0x05;
const LAN8742_REG_SECR: u8 = 0x1A;
const LAN8742_REG_PHYSCSR: u8 = 0x1F;

pub(crate) struct Lan8742ProbePhy<SM: StationManagement> {
    inner: GenericPhy<SM>,
    link_up: bool,
}

impl<SM: StationManagement> Lan8742ProbePhy<SM> {
    pub(crate) fn new_auto(sm: SM) -> Self {
        Self {
            inner: GenericPhy::new_auto(sm),
            link_up: false,
        }
    }

    fn read_register(&mut self, reg: u8) -> u16 {
        self.inner
            .station_management()
            .smi_read(LAN8742_PHY_ADDR, reg)
    }

    fn sample_phy_probes(&mut self, link_up: bool) {
        let secr = self.read_register(LAN8742_REG_SECR);
        #[cfg(feature = "product")]
        M7_ETH_PHY_SECR_RAW_SNAPSHOT.store(u32::from(secr), Ordering::Relaxed);

        let link_rose = link_up && !self.link_up;
        self.link_up = link_up;
        if link_rose {
            let anlpar = self.read_register(LAN8742_REG_ANLPAR);
            let physcsr = self.read_register(LAN8742_REG_PHYSCSR);
            #[cfg(feature = "product")]
            {
                M7_ETH_PHY_ANLPAR_SNAPSHOT.store(u32::from(anlpar), Ordering::Relaxed);
                M7_ETH_PHY_PHYSCSR_SNAPSHOT.store(u32::from(physcsr), Ordering::Relaxed);
            }
        }
    }
}

impl<SM: StationManagement> Phy for Lan8742ProbePhy<SM> {
    fn phy_reset(&mut self) {
        self.inner.phy_reset();
    }

    fn phy_init(&mut self) {
        self.inner.phy_init();
    }

    fn poll_link(&mut self, cx: &mut Context) -> bool {
        let link_up = self.inner.poll_link(cx);
        self.sample_phy_probes(link_up);
        link_up
    }
}
