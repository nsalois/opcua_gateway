//! Opta M7 production clock tree and clock-coupled Ethernet constants.

// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
use embassy_stm32::gpio::Speed;
use embassy_stm32::rcc::mux::Usbsel;
use embassy_stm32::rcc::{
    AHBPrescaler, APBPrescaler, HSIPrescaler, Hse, HseMode, Hsi48Config, Mco1Source, McoConfig,
    McoPrescaler, Pll, PllDiv, PllMul, PllPreDiv, PllSource, SMPSSupplyVoltage, SupplyConfig,
    Sysclk, TimerPrescaler, VoltageScale, HSI48_FREQ, HSI_FREQ,
};
use embassy_stm32::time::Hertz;

/// Frequencies derived from the exact RCC values in a [`ClockPlan`].
#[derive(Clone, Copy)]
pub(crate) struct ClockFrequencies {
    pub(crate) hse_hz: u32,
    pub(crate) system_hz: u32,
    pub(crate) m7_hz: u32,
    pub(crate) ahb_hz: u32,
    pub(crate) apb1_hz: u32,
    pub(crate) apb2_hz: u32,
    pub(crate) apb3_hz: u32,
    pub(crate) apb4_hz: u32,
    pub(crate) tim2_kernel_hz: u32,
    pub(crate) usb_hz: u32,
    pub(crate) mdc_hz: u32,
}

/// Raw H7 MDIO clock-range encoding and its corresponding HCLK divisor.
#[derive(Clone, Copy)]
pub(crate) struct RawMdioClock {
    pub(crate) clock_range: u32,
    pub(crate) divisor: u32,
}

/// One immutable description of every production clock value configured by
/// this image or consumed by clock-coupled firmware.
pub(crate) struct ClockPlan {
    supply_config: SupplyConfig,
    voltage_scale: VoltageScale,
    hsi: Option<HSIPrescaler>,
    hse: Hse,
    hsi48: Option<Hsi48Config>,
    pll1: Pll,
    sys: Sysclk,
    d1c_pre: AHBPrescaler,
    ahb_pre: AHBPrescaler,
    apb1_pre: APBPrescaler,
    apb2_pre: APBPrescaler,
    apb3_pre: APBPrescaler,
    apb4_pre: APBPrescaler,
    timer_prescaler: TimerPrescaler,
    usbsel: Usbsel,
    mco1_source: Mco1Source,
    mco1_prescaler: McoPrescaler,
    mco1_speed: Speed,
}

/// The only production clock-plan value. Configuration, reporting, timer
/// derivation, and raw MDIO encoding all consume this value.
pub(crate) const PRODUCTION_CLOCK_PLAN: ClockPlan = ClockPlan {
    supply_config: SupplyConfig::SMPSLDO(SMPSSupplyVoltage::V1_8),
    voltage_scale: VoltageScale::Scale1,
    hsi: Some(HSIPrescaler::DIV1),
    hse: Hse {
        freq: Hertz(25_000_000),
        mode: HseMode::Bypass,
    },
    hsi48: Some(Hsi48Config::new()),
    pll1: Pll {
        source: PllSource::HSE,
        prediv: PllPreDiv::DIV5,
        mul: PllMul::MUL160,
        divp: Some(PllDiv::DIV2),
        divq: None,
        divr: None,
    },
    sys: Sysclk::PLL1_P,
    d1c_pre: AHBPrescaler::DIV1,
    ahb_pre: AHBPrescaler::DIV2,
    apb1_pre: APBPrescaler::DIV2,
    apb2_pre: APBPrescaler::DIV2,
    apb3_pre: APBPrescaler::DIV2,
    apb4_pre: APBPrescaler::DIV2,
    timer_prescaler: TimerPrescaler::DefaultX2,
    usbsel: Usbsel::HSI48,
    mco1_source: Mco1Source::HSE,
    mco1_prescaler: McoPrescaler::DIV1,
    mco1_speed: Speed::VeryHigh,
};

/// Compile-time raw-MDIO encoding for the production HCLK. Runtime PHY
/// accesses consume these literal fields without re-projecting the clock tree.
pub(crate) const PRODUCTION_MDIO: RawMdioClock = PRODUCTION_CLOCK_PLAN.mdio_encoding();

/// Compile-time projection of the one production plan for report consumers.
pub(crate) const PRODUCTION_CLOCK_FREQUENCIES: ClockFrequencies =
    PRODUCTION_CLOCK_PLAN.frequencies();

impl ClockPlan {
    /// Build the Embassy RCC configuration directly from this plan.
    pub(crate) fn embassy_config(&self) -> embassy_stm32::Config {
        let mut config = embassy_stm32::Config::default();
        config.rcc.supply_config = self.supply_config;
        config.rcc.voltage_scale = self.voltage_scale;
        config.rcc.hsi = self.hsi;
        config.rcc.hse = Some(self.hse);
        config.rcc.hsi48 = self.hsi48;
        config.rcc.pll1 = Some(self.pll1);
        config.rcc.sys = self.sys;
        config.rcc.d1c_pre = self.d1c_pre;
        config.rcc.ahb_pre = self.ahb_pre;
        config.rcc.apb1_pre = self.apb1_pre;
        config.rcc.apb2_pre = self.apb2_pre;
        config.rcc.apb3_pre = self.apb3_pre;
        config.rcc.apb4_pre = self.apb4_pre;
        config.rcc.timer_prescaler = self.timer_prescaler;
        config.rcc.mux.usbsel = self.usbsel;
        config
    }

    pub(crate) fn mco1_source(&self) -> Mco1Source {
        self.mco1_source
    }

    pub(crate) fn mco1_config(&self) -> McoConfig {
        let mut config = McoConfig::default();
        config.prescaler = self.mco1_prescaler;
        config.speed = self.mco1_speed;
        config
    }

    pub(crate) const fn pll1_predivisor(&self) -> u32 {
        // WHY: STM32H7 DIVM stores the divider itself, while DIVN and DIVP
        // store their values minus one.
        self.pll1.prediv.to_bits() as u32
    }

    pub(crate) const fn pll1_multiplier(&self) -> u32 {
        self.pll1.mul.to_bits() as u32 + 1
    }

    pub(crate) const fn pll1_p_divisor(&self) -> u32 {
        match self.pll1.divp {
            Some(divisor) => divisor.to_bits() as u32 + 1,
            None => panic!("production PLL1P output must be enabled"),
        }
    }

    pub(crate) const fn mdio_encoding(&self) -> RawMdioClock {
        raw_mdio_clock_for_hclk(self.ahb_hz())
    }

    /// Derive every reported domain frequency from the same RCC fields copied
    /// into [`Self::embassy_config`].
    pub(crate) const fn frequencies(&self) -> ClockFrequencies {
        let system_hz = self.system_hz();
        let ahb_hz = self.ahb_hz();
        let mdio = self.mdio_encoding();
        ClockFrequencies {
            hse_hz: self.hse.freq.0,
            system_hz,
            m7_hz: system_hz / ahb_divisor(self.d1c_pre),
            ahb_hz,
            apb1_hz: ahb_hz / apb_divisor(self.apb1_pre),
            apb2_hz: ahb_hz / apb_divisor(self.apb2_pre),
            apb3_hz: ahb_hz / apb_divisor(self.apb3_pre),
            apb4_hz: ahb_hz / apb_divisor(self.apb4_pre),
            tim2_kernel_hz: timer_kernel_hz(ahb_hz, self.apb1_pre, self.timer_prescaler),
            usb_hz: self.usb_hz(),
            mdc_hz: ahb_hz / mdio.divisor,
        }
    }

    const fn ahb_hz(&self) -> u32 {
        self.system_hz() / ahb_divisor(self.ahb_pre)
    }

    const fn system_hz(&self) -> u32 {
        match self.sys {
            Sysclk::PLL1_P => self.pll1_p_hz(),
            Sysclk::HSE => self.hse.freq.0,
            Sysclk::HSI => hsi_hz(self.hsi),
            _ => panic!("unsupported production system-clock source"),
        }
    }

    const fn pll1_p_hz(&self) -> u32 {
        let source_hz = match self.pll1.source {
            PllSource::HSE => self.hse.freq.0,
            PllSource::HSI => hsi_hz(self.hsi),
            _ => panic!("unsupported production PLL1 source"),
        };
        (source_hz / self.pll1_predivisor()) * self.pll1_multiplier() / self.pll1_p_divisor()
    }

    const fn usb_hz(&self) -> u32 {
        match (self.usbsel, self.hsi48) {
            (Usbsel::HSI48, Some(_)) => HSI48_FREQ.0,
            _ => panic!("production USB clock must use enabled HSI48"),
        }
    }
}

const fn hsi_hz(prescaler: Option<HSIPrescaler>) -> u32 {
    let divisor = match prescaler {
        Some(HSIPrescaler::DIV1) => 1,
        Some(HSIPrescaler::DIV2) => 2,
        Some(HSIPrescaler::DIV4) => 4,
        Some(HSIPrescaler::DIV8) => 8,
        _ => panic!("production HSI must be enabled with a supported prescaler"),
    };
    HSI_FREQ.0 / divisor
}

const fn ahb_divisor(prescaler: AHBPrescaler) -> u32 {
    match prescaler {
        AHBPrescaler::DIV1 => 1,
        AHBPrescaler::DIV2 => 2,
        AHBPrescaler::DIV4 => 4,
        AHBPrescaler::DIV8 => 8,
        AHBPrescaler::DIV16 => 16,
        AHBPrescaler::DIV64 => 64,
        AHBPrescaler::DIV128 => 128,
        AHBPrescaler::DIV256 => 256,
        AHBPrescaler::DIV512 => 512,
        _ => panic!("unsupported production AHB prescaler"),
    }
}

const fn apb_divisor(prescaler: APBPrescaler) -> u32 {
    match prescaler {
        APBPrescaler::DIV1 => 1,
        APBPrescaler::DIV2 => 2,
        APBPrescaler::DIV4 => 4,
        APBPrescaler::DIV8 => 8,
        APBPrescaler::DIV16 => 16,
        _ => panic!("unsupported production APB prescaler"),
    }
}

/// Const mirror of Embassy H7 v2 `eth/sma/v2.rs`. Keeping every range makes
/// the transcription directly reviewable against the vendored HAL and keeps
/// unsupported HCLK values fail-closed.
const fn raw_mdio_clock_for_hclk(hclk_hz: u32) -> RawMdioClock {
    match hclk_hz / 1_000_000 {
        0..=34 => RawMdioClock {
            clock_range: 2,
            divisor: 16,
        },
        35..=59 => RawMdioClock {
            clock_range: 3,
            divisor: 26,
        },
        60..=99 => RawMdioClock {
            clock_range: 0,
            divisor: 42,
        },
        100..=149 => RawMdioClock {
            clock_range: 1,
            divisor: 62,
        },
        150..=249 => RawMdioClock {
            clock_range: 4,
            divisor: 102,
        },
        250..=310 => RawMdioClock {
            clock_range: 5,
            divisor: 124,
        },
        _ => panic!("HCLK is outside the supported H7 v2 raw-MDIO range"),
    }
}

/// Const mirror of Embassy H7 `apb_div_tim`. Embassy's generated prescaler
/// operators are not const, so the production acceptance pins cannot call the
/// HAL implementation directly.
const fn timer_kernel_hz(
    ahb_hz: u32,
    apb_prescaler: APBPrescaler,
    timer_prescaler: TimerPrescaler,
) -> u32 {
    match (timer_prescaler, apb_prescaler) {
        (TimerPrescaler::DefaultX2, APBPrescaler::DIV1)
        | (TimerPrescaler::DefaultX2, APBPrescaler::DIV2)
        | (TimerPrescaler::DefaultX4, APBPrescaler::DIV1)
        | (TimerPrescaler::DefaultX4, APBPrescaler::DIV2)
        | (TimerPrescaler::DefaultX4, APBPrescaler::DIV4) => ahb_hz,
        (TimerPrescaler::DefaultX2, APBPrescaler::DIV4)
        | (TimerPrescaler::DefaultX4, APBPrescaler::DIV8) => ahb_hz / 2,
        (TimerPrescaler::DefaultX2, APBPrescaler::DIV8)
        | (TimerPrescaler::DefaultX4, APBPrescaler::DIV16) => ahb_hz / 4,
        (TimerPrescaler::DefaultX2, APBPrescaler::DIV16) => ahb_hz / 8,
        _ => panic!("unsupported production timer prescaler"),
    }
}

// Preserve the accepted 400/200/100 MHz plan and its clock-coupled encodings.
// These assertions are acceptance pins, not a second source used by firmware.
const _: () = {
    let frequencies = PRODUCTION_CLOCK_FREQUENCIES;
    assert!(PRODUCTION_CLOCK_PLAN.pll1_predivisor() == 5);
    assert!(PRODUCTION_CLOCK_PLAN.pll1_multiplier() == 160);
    assert!(PRODUCTION_CLOCK_PLAN.pll1_p_divisor() == 2);
    assert!(frequencies.system_hz == 400_000_000);
    assert!(frequencies.m7_hz == 400_000_000);
    assert!(frequencies.ahb_hz == 200_000_000);
    assert!(frequencies.apb1_hz == 100_000_000);
    assert!(frequencies.apb2_hz == 100_000_000);
    assert!(frequencies.apb3_hz == 100_000_000);
    assert!(frequencies.apb4_hz == 100_000_000);
    assert!(frequencies.tim2_kernel_hz == 200_000_000);
    assert!(frequencies.usb_hz == 48_000_000);
    assert!(PRODUCTION_MDIO.clock_range == 4);
    assert!(PRODUCTION_MDIO.divisor == 102);
    assert!(frequencies.mdc_hz >= 1_000_000 && frequencies.mdc_hz <= 2_500_000);

    // Pin every accepted H7 v2 range transition to the vendored Embassy map.
    let mdio = raw_mdio_clock_for_hclk(34_999_999);
    assert!(mdio.clock_range == 2 && mdio.divisor == 16);
    let mdio = raw_mdio_clock_for_hclk(35_000_000);
    assert!(mdio.clock_range == 3 && mdio.divisor == 26);
    let mdio = raw_mdio_clock_for_hclk(59_999_999);
    assert!(mdio.clock_range == 3 && mdio.divisor == 26);
    let mdio = raw_mdio_clock_for_hclk(60_000_000);
    assert!(mdio.clock_range == 0 && mdio.divisor == 42);
    let mdio = raw_mdio_clock_for_hclk(99_999_999);
    assert!(mdio.clock_range == 0 && mdio.divisor == 42);
    let mdio = raw_mdio_clock_for_hclk(100_000_000);
    assert!(mdio.clock_range == 1 && mdio.divisor == 62);
    let mdio = raw_mdio_clock_for_hclk(149_999_999);
    assert!(mdio.clock_range == 1 && mdio.divisor == 62);
    let mdio = raw_mdio_clock_for_hclk(150_000_000);
    assert!(mdio.clock_range == 4 && mdio.divisor == 102);
    let mdio = raw_mdio_clock_for_hclk(249_999_999);
    assert!(mdio.clock_range == 4 && mdio.divisor == 102);
    let mdio = raw_mdio_clock_for_hclk(250_000_000);
    assert!(mdio.clock_range == 5 && mdio.divisor == 124);
    let mdio = raw_mdio_clock_for_hclk(310_999_999);
    assert!(mdio.clock_range == 5 && mdio.divisor == 124);
};

/// Put an inherited bootloader clock tree into the state Embassy's H7 clock
/// initializer requires.
///
/// The Opta boot chain leaves PLL1 running. STM32H7 PLL divider fields are
/// writable only while that PLL is disabled, while Embassy 0.6's configured
/// PLL path assumes it starts disabled. Switch the live system clock to the
/// ready HSI first, then stop PLL1 and HSE, waiting for each hardware
/// acknowledgement. This leaves HSE disabled so Embassy may safely select
/// bypass mode before restarting it. This must run immediately before
/// `embassy_stm32::init_primary`, before any product peripheral or
/// interrupt-driven task is initialized.
pub(crate) fn quiesce_inherited_pll1() {
    stm32_metapac::RCC.cr().modify(|w| w.set_hsion(true));
    while !stm32_metapac::RCC.cr().read().hsirdy() {}

    stm32_metapac::RCC.cfgr().modify(|w| w.set_sw(Sysclk::HSI));
    while stm32_metapac::RCC.cfgr().read().sws() != Sysclk::HSI {}

    stm32_metapac::RCC.cr().modify(|w| w.set_pllon(0, false));
    while stm32_metapac::RCC.cr().read().pllrdy(0) {}

    stm32_metapac::RCC.cr().modify(|w| w.set_hseon(false));
    while stm32_metapac::RCC.cr().read().hserdy() {}
}
