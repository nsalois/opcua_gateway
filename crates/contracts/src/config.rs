use core::fmt;

pub const DEVICE_NAME_BYTES: usize = 32;
pub const BUCHI_USER_BYTES: usize = 32;
pub const BUCHI_PASSWORD_BYTES: usize = 64;
pub const SLOT_SIZE: usize = 128 * 1024;
pub const SLOT_A_ADDR: u32 = 0x080C_0000;
pub const SLOT_B_ADDR: u32 = 0x080E_0000;
pub const SLOT_A_SECTOR_IN_BANK: u8 = 6;
pub const SLOT_B_SECTOR_IN_BANK: u8 = 7;
pub const LEGACY_RECORD_SIZE: usize = 256;
pub const LEGACY_RECORD_BODY_SIZE: usize = 224;
pub const MAX_TRUST_CA_DER_BYTES: usize = 2048;
pub const RECORD_BODY_SIZE: usize = 2304;
pub const RECORD_SIZE: usize = 2336;
pub const FLASH_WRITE_GRANULE: usize = 32;
pub const MAGIC: u32 = 0x4643_504F; // "OPCF" little-endian bytes.
pub const LEGACY_VERSION: u16 = 1;
pub const VERSION: u16 = 2;
pub const VALID_MARKER: u32 = 0xC0DE_7A17;
const CRC_OFFSET: usize = 20;
const PAYLOAD_OFFSET: usize = 24;
const LEGACY_MARKER_OFFSET: usize = LEGACY_RECORD_BODY_SIZE;
const MARKER_OFFSET: usize = RECORD_BODY_SIZE;
const TRUST_CA_LEN_OFFSET: usize = LEGACY_RECORD_BODY_SIZE;
const TRUST_FLAGS_OFFSET: usize = TRUST_CA_LEN_OFFSET + 2;
/// One byte of the existing 28-byte reserved gap between trust metadata
/// and CA storage. It is inside the CRC-covered body.
pub const RECORD_KIND_OFFSET: usize = TRUST_FLAGS_OFFSET + 2;
const TRUST_CA_OFFSET: usize = 256;
const TRUST_FLAG_TIME_PROVISIONED: u16 = 1 << 0;
const TRUST_KNOWN_FLAGS: u16 = TRUST_FLAG_TIME_PROVISIONED;
const ERASED_U32: u32 = 0xFFFF_FFFF;
pub const MIN_TRUST_UNIX_SECONDS: u64 = 1_704_067_200; // 2024-01-01T00:00:00Z.
pub const MAX_TRUST_UNIX_SECONDS: u64 = 4_102_444_799; // 2099-12-31T23:59:59Z.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    Empty,
    TooLong,
    NonAscii,
    InvalidDeviceName,
    InvalidCredential,
    InvalidIpv4,
    InvalidNetMode,
    InvalidNetmask,
    StaticAddressRequired,
    StaticNetmaskRequired,
    InvalidBool,
    UnknownKey,
    MalformedRecord,
    CrcMismatch,
    MissingValidMarker,
    TrustCaTooLong,
    MalformedTrust,
}

impl ConfigError {
    pub const fn as_str(self) -> &'static str {
        match self {
            ConfigError::Empty => "empty",
            ConfigError::TooLong => "too-long",
            ConfigError::NonAscii => "non-ascii",
            ConfigError::InvalidDeviceName => "invalid-device-name",
            ConfigError::InvalidCredential => "invalid-credential",
            ConfigError::InvalidIpv4 => "invalid-ipv4",
            ConfigError::InvalidNetMode => "invalid-net-mode",
            ConfigError::InvalidNetmask => "invalid-netmask",
            ConfigError::StaticAddressRequired => "static-address-required",
            ConfigError::StaticNetmaskRequired => "static-netmask-required",
            ConfigError::InvalidBool => "invalid-bool",
            ConfigError::UnknownKey => "unknown-key",
            ConfigError::MalformedRecord => "malformed-record",
            ConfigError::CrcMismatch => "crc-mismatch",
            ConfigError::MissingValidMarker => "missing-valid-marker",
            ConfigError::TrustCaTooLong => "trust-ca-too-long",
            ConfigError::MalformedTrust => "malformed-trust",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GatewayTrust {
    ca_der_len: u16,
    flags: u16,
    ca_der: [u8; MAX_TRUST_CA_DER_BYTES],
}

impl GatewayTrust {
    pub const fn missing() -> Self {
        Self {
            ca_der_len: 0,
            flags: 0,
            ca_der: [0; MAX_TRUST_CA_DER_BYTES],
        }
    }

    pub fn from_ca_der(ca_der: &[u8], time_provisioned: bool) -> Result<Self, ConfigError> {
        let mut trust = Self::missing();
        trust.replace_ca_der(ca_der)?;
        trust.set_time_provisioned(time_provisioned);
        Ok(trust)
    }

    /// Replace only the CA bytes, preserving the ever-provisioned-time marker.
    pub fn replace_ca_der(&mut self, ca_der: &[u8]) -> Result<(), ConfigError> {
        if ca_der.len() > MAX_TRUST_CA_DER_BYTES {
            return Err(ConfigError::TrustCaTooLong);
        }
        self.ca_der.fill(0);
        self.ca_der[..ca_der.len()].copy_from_slice(ca_der);
        self.ca_der_len = ca_der.len() as u16;
        Ok(())
    }

    pub const fn ca_der_len(&self) -> usize {
        self.ca_der_len as usize
    }

    pub const fn is_anchor_present(&self) -> bool {
        self.ca_der_len != 0
    }

    pub const fn time_provisioned(&self) -> bool {
        self.flags & TRUST_FLAG_TIME_PROVISIONED != 0
    }

    pub const fn is_complete(&self) -> bool {
        self.is_anchor_present() && self.time_provisioned()
    }

    pub fn ca_der(&self) -> &[u8] {
        &self.ca_der[..self.ca_der_len()]
    }

    pub fn set_time_provisioned(&mut self, provisioned: bool) {
        if provisioned {
            self.flags |= TRUST_FLAG_TIME_PROVISIONED;
        } else {
            self.flags &= !TRUST_FLAG_TIME_PROVISIONED;
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.ca_der_len() > MAX_TRUST_CA_DER_BYTES {
            return Err(ConfigError::TrustCaTooLong);
        }
        if self.flags & !TRUST_KNOWN_FLAGS != 0 {
            return Err(ConfigError::MalformedTrust);
        }
        Ok(())
    }
}

impl Default for GatewayTrust {
    fn default() -> Self {
        Self::missing()
    }
}

impl fmt::Debug for GatewayTrust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayTrust")
            .field("ca_der_len", &self.ca_der_len())
            .field("time_provisioned", &self.time_provisioned())
            .finish()
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustState {
    Missing = 0,
    Provisioned = 1,
    Verified = 2,
    VerifyRejected = 3,
    Revoked = 4,
}

impl TrustState {
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Missing),
            1 => Some(Self::Provisioned),
            2 => Some(Self::Verified),
            3 => Some(Self::VerifyRejected),
            4 => Some(Self::Revoked),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Provisioned => "provisioned",
            Self::Verified => "verified",
            Self::VerifyRejected => "verify-rejected",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustUploadError {
    InvalidLength,
    NotStarted,
    EmptyChunk,
    OddHexLength,
    InvalidHex,
    ExceedsDeclaredLength,
    Incomplete,
}

impl TrustUploadError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidLength => "trust-upload-invalid-length",
            Self::NotStarted => "trust-upload-not-started",
            Self::EmptyChunk => "trust-upload-empty-chunk",
            Self::OddHexLength => "trust-upload-odd-hex-length",
            Self::InvalidHex => "trust-upload-invalid-hex",
            Self::ExceedsDeclaredLength => "trust-upload-exceeds-length",
            Self::Incomplete => "trust-upload-incomplete",
        }
    }
}

pub struct TrustUpload {
    expected_len: u16,
    received_len: u16,
    active: bool,
    bytes: [u8; MAX_TRUST_CA_DER_BYTES],
}

impl TrustUpload {
    pub const fn new() -> Self {
        Self {
            expected_len: 0,
            received_len: 0,
            active: false,
            bytes: [0; MAX_TRUST_CA_DER_BYTES],
        }
    }

    pub fn begin(&mut self, expected_len: usize) -> Result<(), TrustUploadError> {
        if expected_len == 0 || expected_len > MAX_TRUST_CA_DER_BYTES {
            return Err(TrustUploadError::InvalidLength);
        }
        self.reset();
        self.expected_len = expected_len as u16;
        self.active = true;
        Ok(())
    }

    pub fn append_hex(&mut self, hex: &str) -> Result<usize, TrustUploadError> {
        if !self.active {
            return Err(TrustUploadError::NotStarted);
        }
        if hex.is_empty() {
            return Err(TrustUploadError::EmptyChunk);
        }
        if !hex.len().is_multiple_of(2) {
            return Err(TrustUploadError::OddHexLength);
        }
        let decoded_len = hex.len() / 2;
        let start = self.received_len as usize;
        if start + decoded_len > self.expected_len as usize {
            return Err(TrustUploadError::ExceedsDeclaredLength);
        }
        let input = hex.as_bytes();
        for index in 0..decoded_len {
            let high = decode_hex_nibble(input[index * 2])?;
            let low = decode_hex_nibble(input[index * 2 + 1])?;
            self.bytes[start + index] = (high << 4) | low;
        }
        self.received_len += decoded_len as u16;
        Ok(decoded_len)
    }

    pub const fn expected_len(&self) -> usize {
        self.expected_len as usize
    }

    pub const fn received_len(&self) -> usize {
        self.received_len as usize
    }

    pub const fn is_complete(&self) -> bool {
        self.active && self.received_len == self.expected_len
    }

    pub fn ca_der(&self) -> Result<&[u8], TrustUploadError> {
        if !self.active {
            return Err(TrustUploadError::NotStarted);
        }
        if !self.is_complete() {
            return Err(TrustUploadError::Incomplete);
        }
        Ok(&self.bytes[..self.expected_len()])
    }

    pub fn reset(&mut self) {
        self.bytes.fill(0);
        self.expected_len = 0;
        self.received_len = 0;
        self.active = false;
    }
}

impl Default for TrustUpload {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UtcDateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    /// ISO weekday: Monday = 1 through Sunday = 7.
    pub weekday: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

pub fn unix_seconds_to_utc(seconds: u64) -> Result<UtcDateTime, ConfigError> {
    if !(MIN_TRUST_UNIX_SECONDS..=MAX_TRUST_UNIX_SECONDS).contains(&seconds) {
        return Err(ConfigError::MalformedTrust);
    }
    let days = (seconds / 86_400) as i64;
    let seconds_of_day = seconds % 86_400;
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    Ok(UtcDateTime {
        year: year as u16,
        month: month as u8,
        day: day as u8,
        weekday: ((days + 3) % 7 + 1) as u8,
        hour: (seconds_of_day / 3_600) as u8,
        minute: ((seconds_of_day % 3_600) / 60) as u8,
        second: (seconds_of_day % 60) as u8,
    })
}

pub fn utc_to_unix_seconds(datetime: UtcDateTime) -> Result<u64, ConfigError> {
    if datetime.weekday == 0
        || datetime.weekday > 7
        || datetime.month == 0
        || datetime.month > 12
        || datetime.day == 0
        || datetime.day > days_in_month(datetime.year, datetime.month)
        || datetime.hour > 23
        || datetime.minute > 59
        || datetime.second > 59
    {
        return Err(ConfigError::MalformedTrust);
    }
    let year = i64::from(datetime.year) - if datetime.month <= 2 { 1 } else { 0 };
    let era = year / 400;
    let year_of_era = year - era * 400;
    let month_prime = i64::from(datetime.month) + if datetime.month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + i64::from(datetime.day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    if days < 0 {
        return Err(ConfigError::MalformedTrust);
    }
    let seconds = days as u64 * 86_400
        + u64::from(datetime.hour) * 3_600
        + u64::from(datetime.minute) * 60
        + u64::from(datetime.second);
    if !(MIN_TRUST_UNIX_SECONDS..=MAX_TRUST_UNIX_SECONDS).contains(&seconds) {
        return Err(ConfigError::MalformedTrust);
    }
    Ok(seconds)
}

const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100)) => {
            29
        }
        2 => 28,
        _ => 0,
    }
}

fn decode_hex_nibble(byte: u8) -> Result<u8, TrustUploadError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(TrustUploadError::InvalidHex),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedAscii<const N: usize> {
    len: u8,
    bytes: [u8; N],
}

impl<const N: usize> FixedAscii<N> {
    pub const fn empty() -> Self {
        Self {
            len: 0,
            bytes: [0; N],
        }
    }

    pub fn try_from_str(value: &str) -> Result<Self, ConfigError> {
        if value.len() > N {
            return Err(ConfigError::TooLong);
        }
        if !value.is_ascii() {
            return Err(ConfigError::NonAscii);
        }
        let mut out = Self::empty();
        let bytes = value.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            out.bytes[index] = bytes[index];
            index += 1;
        }
        out.len = bytes.len() as u8;
        Ok(out)
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, ConfigError> {
        if bytes.len() > N {
            return Err(ConfigError::TooLong);
        }
        let mut out = Self::empty();
        let mut index = 0;
        while index < bytes.len() {
            let byte = bytes[index];
            if !byte.is_ascii() {
                return Err(ConfigError::NonAscii);
            }
            out.bytes[index] = byte;
            index += 1;
        }
        out.len = bytes.len() as u8;
        Ok(out)
    }

    pub const fn len(&self) -> usize {
        self.len as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len()]
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("")
    }

    fn write_to(&self, out: &mut [u8], len_offset: usize, bytes_offset: usize) {
        out[len_offset] = self.len;
        let mut index = 0;
        while index < N {
            out[bytes_offset + index] = if index < self.len() {
                self.bytes[index]
            } else {
                0
            };
            index += 1;
        }
    }

    fn read_from(
        input: &[u8],
        len_offset: usize,
        bytes_offset: usize,
    ) -> Result<Self, ConfigError> {
        let len = input[len_offset] as usize;
        if len > N {
            return Err(ConfigError::MalformedRecord);
        }
        Self::try_from_bytes(&input[bytes_offset..bytes_offset + len])
    }
}

impl<const N: usize> Default for FixedAscii<N> {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetMode {
    Dhcp,
    Static,
}

impl NetMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            NetMode::Dhcp => "dhcp",
            NetMode::Static => "static",
        }
    }

    pub const fn to_byte(self) -> u8 {
        match self {
            NetMode::Dhcp => 0,
            NetMode::Static => 1,
        }
    }

    pub const fn from_byte(byte: u8) -> Result<Self, ConfigError> {
        match byte {
            0 => Ok(NetMode::Dhcp),
            1 => Ok(NetMode::Static),
            _ => Err(ConfigError::InvalidNetMode),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasswordState {
    Missing,
    Set,
}

impl PasswordState {
    pub const fn as_str(self) -> &'static str {
        match self {
            PasswordState::Missing => "missing",
            PasswordState::Set => "set",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigKey {
    DeviceName,
    NetMode,
    StaticIp,
    StaticNetmask,
    StaticGateway,
    StaticDns,
    BuchiIp,
    BuchiUser,
    BuchiPassword,
    WriteEnable,
}

impl ConfigKey {
    pub fn parse(key: &str) -> Result<Self, ConfigError> {
        match key {
            "device-name" => Ok(Self::DeviceName),
            "net-mode" => Ok(Self::NetMode),
            "static-ip" => Ok(Self::StaticIp),
            "static-netmask" => Ok(Self::StaticNetmask),
            "static-gateway" => Ok(Self::StaticGateway),
            "static-dns" => Ok(Self::StaticDns),
            "buchi-ip" => Ok(Self::BuchiIp),
            "buchi-user" => Ok(Self::BuchiUser),
            "buchi-password" => Ok(Self::BuchiPassword),
            "write-enable" => Ok(Self::WriteEnable),
            _ => Err(ConfigError::UnknownKey),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            ConfigKey::DeviceName => "device-name",
            ConfigKey::NetMode => "net-mode",
            ConfigKey::StaticIp => "static-ip",
            ConfigKey::StaticNetmask => "static-netmask",
            ConfigKey::StaticGateway => "static-gateway",
            ConfigKey::StaticDns => "static-dns",
            ConfigKey::BuchiIp => "buchi-ip",
            ConfigKey::BuchiUser => "buchi-user",
            ConfigKey::BuchiPassword => "buchi-password",
            ConfigKey::WriteEnable => "write-enable",
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct GatewayConfig {
    pub device_name: FixedAscii<DEVICE_NAME_BYTES>,
    pub net_mode: NetMode,
    pub static_ip: [u8; 4],
    pub static_netmask: [u8; 4],
    pub static_gateway: [u8; 4],
    pub static_dns: [u8; 4],
    pub buchi_ip: [u8; 4],
    pub buchi_user: FixedAscii<BUCHI_USER_BYTES>,
    pub buchi_password: FixedAscii<BUCHI_PASSWORD_BYTES>,
    pub write_enable: bool,
}

impl fmt::Debug for GatewayConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayConfig")
            .field("device_name", &self.device_name.as_str())
            .field("net_mode", &self.net_mode)
            .field("static_ip", &Ipv4Display(self.static_ip))
            .field("static_netmask", &Ipv4Display(self.static_netmask))
            .field("static_gateway", &Ipv4Display(self.static_gateway))
            .field("static_dns", &Ipv4Display(self.static_dns))
            .field("buchi_ip", &Ipv4Display(self.buchi_ip))
            .field("buchi_user", &self.buchi_user.as_str())
            .field("buchi_password", &self.password_state().as_str())
            .field("write_enable", &self.write_enable)
            .finish()
    }
}

impl GatewayConfig {
    pub fn defaults_from_mac(mac: [u8; 6]) -> Self {
        let mut name_bytes = [0u8; DEVICE_NAME_BYTES];
        let prefix = b"opta-gw-";
        let mut index = 0;
        while index < prefix.len() {
            name_bytes[index] = prefix[index];
            index += 1;
        }
        write_hex_byte(&mut name_bytes, prefix.len(), mac[4]);
        write_hex_byte(&mut name_bytes, prefix.len() + 2, mac[5]);
        Self {
            device_name: FixedAscii {
                len: 12,
                bytes: name_bytes,
            },
            net_mode: NetMode::Dhcp,
            static_ip: [0, 0, 0, 0],
            static_netmask: [0, 0, 0, 0],
            static_gateway: [0, 0, 0, 0],
            static_dns: [0, 0, 0, 0],
            buchi_ip: [0, 0, 0, 0],
            buchi_user: FixedAscii::empty(),
            buchi_password: FixedAscii::empty(),
            write_enable: false,
        }
    }

    /// Factory name uses all UID words in the same order as the device URI.
    /// Saved names and the legacy reset-record encoding remain unchanged.
    pub fn defaults_from_uid(uid: [u32; 3]) -> Self {
        let mut bytes = [0u8; DEVICE_NAME_BYTES];
        bytes[..5].copy_from_slice(b"opta-");
        for (index, byte) in uid.into_iter().flat_map(u32::to_be_bytes).enumerate() {
            write_hex_byte(&mut bytes, 5 + index * 2, byte);
        }
        Self {
            device_name: FixedAscii { len: 29, bytes },
            ..Self::defaults_from_mac([0; 6])
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_device_name(self.device_name.as_str())?;
        validate_credential(self.buchi_user.as_str())?;
        validate_credential(self.buchi_password.as_str())?;
        if matches!(self.net_mode, NetMode::Static) {
            if is_unspecified(self.static_ip) {
                return Err(ConfigError::StaticAddressRequired);
            }
            if is_unspecified(self.static_netmask) {
                return Err(ConfigError::StaticNetmaskRequired);
            }
            netmask_prefix_len(self.static_netmask)?;
        } else if !is_unspecified(self.static_netmask) {
            netmask_prefix_len(self.static_netmask)?;
        }
        Ok(())
    }

    pub const fn password_state(&self) -> PasswordState {
        if self.buchi_password.is_empty() {
            PasswordState::Missing
        } else {
            PasswordState::Set
        }
    }

    pub fn set_key_value(&mut self, key: ConfigKey, value: &str) -> Result<(), ConfigError> {
        match key {
            ConfigKey::DeviceName => {
                validate_device_name(value)?;
                self.device_name = FixedAscii::try_from_str(value)?;
            }
            ConfigKey::NetMode => {
                self.net_mode = match value {
                    "dhcp" => NetMode::Dhcp,
                    "static" => NetMode::Static,
                    _ => return Err(ConfigError::InvalidNetMode),
                };
            }
            ConfigKey::StaticIp => self.static_ip = parse_ipv4(value)?,
            ConfigKey::StaticNetmask => {
                let netmask = parse_ipv4(value)?;
                netmask_prefix_len(netmask)?;
                self.static_netmask = netmask;
            }
            ConfigKey::StaticGateway => self.static_gateway = parse_ipv4(value)?,
            ConfigKey::StaticDns => self.static_dns = parse_ipv4(value)?,
            ConfigKey::BuchiIp => self.buchi_ip = parse_ipv4(value)?,
            ConfigKey::BuchiUser => {
                validate_credential(value)?;
                self.buchi_user = FixedAscii::try_from_str(value)?;
            }
            ConfigKey::BuchiPassword => {
                validate_credential(value)?;
                self.buchi_password = FixedAscii::try_from_str(value)?;
            }
            ConfigKey::WriteEnable => self.write_enable = parse_bool(value)?,
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigSource {
    SlotA,
    SlotB,
    Defaults,
}

impl ConfigSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            ConfigSource::SlotA => "slot-a",
            ConfigSource::SlotB => "slot-b",
            ConfigSource::Defaults => "defaults",
        }
    }
}

/// Semantic kind carried by every valid configuration record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RecordKind {
    Normal = 0,
    Reset = 1,
}

impl RecordKind {
    fn from_byte(value: u8) -> Result<Self, ConfigError> {
        match value {
            0 => Ok(Self::Normal),
            1 => Ok(Self::Reset),
            _ => Err(ConfigError::MalformedRecord),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FactoryResetStep {
    EraseInactive,
    ProgramTombstoneBody,
    ProgramTombstoneMarker,
    EraseOldSlot,
    Readback,
    RevokeRam,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FactoryResetCommitEvidence {
    Uncertain,
    Confirmed,
}

/// Three operator-visible reset result classes. A marker-program failure is
/// conservatively included in the incomplete class with uncertain commit
/// evidence, so callers revoke RAM trust even when readback is unavailable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FactoryResetOutcome {
    NotCommitted,
    CommittedCleanupIncomplete { commit: FactoryResetCommitEvidence },
    CommittedCleanupComplete,
}

impl FactoryResetOutcome {
    pub const fn requires_ram_revocation(self) -> bool {
        !matches!(self, Self::NotCommitted)
    }
}

/// Shared, fault-injectable ordering contract for firmware and host tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FactoryResetState {
    target_slot: ConfigSource,
    old_slot: ConfigSource,
    tombstone_sequence: u64,
    step: FactoryResetStep,
}

impl FactoryResetState {
    pub const fn new(source: ConfigSource, sequence: u64) -> Self {
        let (old_slot, target_slot) = match source {
            ConfigSource::SlotA => (ConfigSource::SlotA, ConfigSource::SlotB),
            ConfigSource::SlotB => (ConfigSource::SlotB, ConfigSource::SlotA),
            ConfigSource::Defaults => (ConfigSource::SlotB, ConfigSource::SlotA),
        };
        Self {
            target_slot,
            old_slot,
            tombstone_sequence: next_record_sequence(sequence),
            step: FactoryResetStep::EraseInactive,
        }
    }

    pub const fn target_slot(self) -> ConfigSource {
        self.target_slot
    }

    pub const fn old_slot(self) -> ConfigSource {
        self.old_slot
    }

    pub const fn tombstone_sequence(self) -> u64 {
        self.tombstone_sequence
    }

    pub const fn step(self) -> FactoryResetStep {
        self.step
    }

    pub fn complete_step(&mut self, completed: FactoryResetStep) -> bool {
        if completed != self.step {
            return false;
        }
        self.step = match self.step {
            FactoryResetStep::EraseInactive => FactoryResetStep::ProgramTombstoneBody,
            FactoryResetStep::ProgramTombstoneBody => FactoryResetStep::ProgramTombstoneMarker,
            FactoryResetStep::ProgramTombstoneMarker => FactoryResetStep::EraseOldSlot,
            FactoryResetStep::EraseOldSlot => FactoryResetStep::Readback,
            FactoryResetStep::Readback => FactoryResetStep::RevokeRam,
            FactoryResetStep::RevokeRam => FactoryResetStep::Complete,
            FactoryResetStep::Complete => return false,
        };
        true
    }

    pub const fn failure_outcome(self) -> FactoryResetOutcome {
        match self.step {
            FactoryResetStep::EraseInactive | FactoryResetStep::ProgramTombstoneBody => {
                FactoryResetOutcome::NotCommitted
            }
            FactoryResetStep::ProgramTombstoneMarker => {
                FactoryResetOutcome::CommittedCleanupIncomplete {
                    commit: FactoryResetCommitEvidence::Uncertain,
                }
            }
            FactoryResetStep::EraseOldSlot
            | FactoryResetStep::Readback
            | FactoryResetStep::RevokeRam => FactoryResetOutcome::CommittedCleanupIncomplete {
                commit: FactoryResetCommitEvidence::Confirmed,
            },
            FactoryResetStep::Complete => FactoryResetOutcome::CommittedCleanupComplete,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedSlot {
    pub valid: bool,
    pub kind: Option<RecordKind>,
    pub version: u16,
    pub sequence: u64,
    pub config: GatewayConfig,
    pub trust: GatewayTrust,
    pub error: Option<ConfigError>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotStatus {
    pub valid: bool,
    pub kind: Option<RecordKind>,
    pub version: u16,
    pub sequence: u64,
    pub error: Option<ConfigError>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadStatus {
    pub source: ConfigSource,
    pub kind: Option<RecordKind>,
    pub version: u16,
    pub sequence: u64,
    pub slot_a: SlotStatus,
    pub slot_b: SlotStatus,
}

impl LoadStatus {
    pub const fn inactive_slot(&self) -> ConfigSource {
        match self.source {
            ConfigSource::SlotA => ConfigSource::SlotB,
            ConfigSource::SlotB | ConfigSource::Defaults => ConfigSource::SlotA,
        }
    }

    pub const fn next_sequence(&self) -> u64 {
        next_record_sequence(self.sequence)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadResult {
    pub source: ConfigSource,
    pub kind: Option<RecordKind>,
    pub version: u16,
    pub sequence: u64,
    pub config: GatewayConfig,
    pub trust: GatewayTrust,
    pub slot_a: SlotStatus,
    pub slot_b: SlotStatus,
}

impl LoadResult {
    pub const fn inactive_slot(&self) -> ConfigSource {
        match self.source {
            ConfigSource::SlotA => ConfigSource::SlotB,
            ConfigSource::SlotB | ConfigSource::Defaults => ConfigSource::SlotA,
        }
    }

    pub const fn next_sequence(&self) -> u64 {
        next_record_sequence(self.sequence)
    }
}

const fn next_record_sequence(sequence: u64) -> u64 {
    if sequence == u64::MAX {
        1
    } else {
        sequence + 1
    }
}

pub fn select_config(slot_a: &[u8], slot_b: &[u8], mac: [u8; 6]) -> LoadResult {
    let mut trust = GatewayTrust::missing();
    let (status, config) = select_config_into(
        slot_a,
        slot_b,
        GatewayConfig::defaults_from_mac(mac),
        &mut trust,
    );
    LoadResult {
        source: status.source,
        kind: status.kind,
        version: status.version,
        sequence: status.sequence,
        config,
        trust,
        slot_a: status.slot_a,
        slot_b: status.slot_b,
    }
}

pub fn select_config_into(
    slot_a: &[u8],
    slot_b: &[u8],
    defaults: GatewayConfig,
    trust_out: &mut GatewayTrust,
) -> (LoadStatus, GatewayConfig) {
    let slot_a_status = inspect_slot(slot_a);
    let slot_b_status = inspect_slot(slot_b);
    let source = match (slot_a_status.valid, slot_b_status.valid) {
        (true, true) => select_two_valid_slots(slot_a_status, slot_b_status),
        (true, false) => ConfigSource::SlotA,
        (false, true) => ConfigSource::SlotB,
        (false, false) => ConfigSource::Defaults,
    };
    *trust_out = GatewayTrust::missing();
    let selected = match source {
        ConfigSource::SlotA => decode_slot_inner(slot_a, trust_out).ok(),
        ConfigSource::SlotB => decode_slot_inner(slot_b, trust_out).ok(),
        ConfigSource::Defaults => None,
    };
    let (kind, version, sequence, config) =
        selected.unwrap_or((RecordKind::Normal, 0, 0, defaults));
    let selected_kind = if matches!(source, ConfigSource::Defaults) {
        None
    } else {
        Some(kind)
    };
    let config = if kind == RecordKind::Reset {
        *trust_out = GatewayTrust::missing();
        defaults
    } else {
        config
    };
    (
        LoadStatus {
            source,
            kind: selected_kind,
            version,
            sequence,
            slot_a: slot_a_status,
            slot_b: slot_b_status,
        },
        config,
    )
}

fn select_two_valid_slots(slot_a: SlotStatus, slot_b: SlotStatus) -> ConfigSource {
    let kind_a = slot_a.kind.unwrap_or(RecordKind::Normal);
    let kind_b = slot_b.kind.unwrap_or(RecordKind::Normal);
    match (kind_a, kind_b) {
        (RecordKind::Normal, RecordKind::Normal) => {
            // Successful alternating writes are adjacent, including MAX -> 1.
            // Resolve that relation before ordinary numeric ordering, as for
            // reset records below. Nonadjacent retained records keep their policy.
            if slot_b.sequence == next_record_sequence(slot_a.sequence) {
                ConfigSource::SlotB
            } else if slot_a.sequence == next_record_sequence(slot_b.sequence) {
                ConfigSource::SlotA
            } else if slot_b.sequence > slot_a.sequence {
                ConfigSource::SlotB
            } else {
                ConfigSource::SlotA
            }
        }
        (RecordKind::Reset, RecordKind::Normal) => {
            if slot_b.sequence == next_record_sequence(slot_a.sequence) {
                ConfigSource::SlotB
            } else {
                ConfigSource::SlotA
            }
        }
        (RecordKind::Normal, RecordKind::Reset) => {
            if slot_a.sequence == next_record_sequence(slot_b.sequence) {
                ConfigSource::SlotA
            } else {
                ConfigSource::SlotB
            }
        }
        (RecordKind::Reset, RecordKind::Reset) => {
            if slot_b.sequence == next_record_sequence(slot_a.sequence) {
                ConfigSource::SlotB
            } else if slot_a.sequence == next_record_sequence(slot_b.sequence)
                || slot_a.sequence >= slot_b.sequence
            {
                ConfigSource::SlotA
            } else {
                ConfigSource::SlotB
            }
        }
    }
}

fn inspect_slot(input: &[u8]) -> SlotStatus {
    match inspect_slot_inner(input) {
        Ok((kind, version, sequence)) => SlotStatus {
            valid: true,
            kind: Some(kind),
            version,
            sequence,
            error: None,
        },
        Err(error) => SlotStatus {
            valid: false,
            kind: None,
            version: 0,
            sequence: 0,
            error: Some(error),
        },
    }
}

pub fn decode_slot(input: &[u8], fallback: GatewayConfig) -> DecodedSlot {
    let mut trust = GatewayTrust::missing();
    match decode_slot_inner(input, &mut trust) {
        Ok((kind, version, sequence, config)) => DecodedSlot {
            valid: true,
            kind: Some(kind),
            version,
            sequence,
            config,
            trust,
            error: None,
        },
        Err(error) => DecodedSlot {
            valid: false,
            kind: None,
            version: 0,
            sequence: 0,
            config: fallback,
            trust: GatewayTrust::missing(),
            error: Some(error),
        },
    }
}

pub fn decode_slot_into(
    input: &[u8],
    trust_out: &mut GatewayTrust,
) -> Result<(RecordKind, u16, u64, GatewayConfig), ConfigError> {
    decode_slot_inner(input, trust_out)
}

fn decode_slot_inner(
    input: &[u8],
    trust_out: &mut GatewayTrust,
) -> Result<(RecordKind, u16, u64, GatewayConfig), ConfigError> {
    let slot = parse_slot(input)?;
    let config = decode_config_payload(slot.payload)?;
    decode_trust_payload_into(slot.version, slot.payload, trust_out)?;
    Ok((slot.kind, slot.version, slot.sequence, config))
}

struct ParsedSlot<'a> {
    kind: RecordKind,
    version: u16,
    sequence: u64,
    payload: &'a [u8],
}

fn parse_slot(input: &[u8]) -> Result<ParsedSlot<'_>, ConfigError> {
    if input.len() < 8 {
        return Err(ConfigError::MalformedRecord);
    }
    let magic = read_u32_le(input, 0)?;
    if magic == ERASED_U32 {
        return Err(ConfigError::MissingValidMarker);
    }
    let version = read_u16_le(input, 4)?;
    let body_len = read_u16_le(input, 6)? as usize;
    let (expected_body_len, marker_offset, record_size) = match version {
        LEGACY_VERSION => (
            LEGACY_RECORD_BODY_SIZE,
            LEGACY_MARKER_OFFSET,
            LEGACY_RECORD_SIZE,
        ),
        VERSION => (RECORD_BODY_SIZE, MARKER_OFFSET, RECORD_SIZE),
        _ => return Err(ConfigError::MalformedRecord),
    };
    if input.len() < record_size || magic != MAGIC || body_len != expected_body_len {
        return Err(ConfigError::MalformedRecord);
    }
    let marker = read_u32_le(input, marker_offset)?;
    if marker != VALID_MARKER {
        return Err(ConfigError::MissingValidMarker);
    }
    let stored_crc = read_u32_le(input, CRC_OFFSET)?;
    let actual_crc = record_crc(input, expected_body_len)?;
    if stored_crc != actual_crc {
        return Err(ConfigError::CrcMismatch);
    }
    let sequence = read_u64_le(input, 8)?;
    let kind = if version == LEGACY_VERSION {
        RecordKind::Normal
    } else {
        RecordKind::from_byte(input[RECORD_KIND_OFFSET])?
    };
    let payload = &input[..expected_body_len];
    Ok(ParsedSlot {
        kind,
        version,
        sequence,
        payload,
    })
}

fn inspect_slot_inner(input: &[u8]) -> Result<(RecordKind, u16, u64), ConfigError> {
    let slot = parse_slot(input)?;
    validate_config_payload(slot.payload)?;
    validate_trust_payload(slot.version, slot.payload)?;
    Ok((slot.kind, slot.version, slot.sequence))
}

fn decode_config_payload(payload: &[u8]) -> Result<GatewayConfig, ConfigError> {
    let config = GatewayConfig {
        device_name: FixedAscii::read_from(payload, PAYLOAD_OFFSET, PAYLOAD_OFFSET + 1)?,
        net_mode: NetMode::from_byte(payload[57])?,
        static_ip: read_ipv4(payload, 58)?,
        static_netmask: read_ipv4(payload, 62)?,
        static_gateway: read_ipv4(payload, 66)?,
        static_dns: read_ipv4(payload, 70)?,
        buchi_ip: read_ipv4(payload, 74)?,
        buchi_user: FixedAscii::read_from(payload, 78, 79)?,
        buchi_password: FixedAscii::read_from(payload, 111, 112)?,
        write_enable: match payload[176] {
            0 => false,
            1 => true,
            _ => return Err(ConfigError::MalformedRecord),
        },
    };
    config.validate()?;
    Ok(config)
}

fn validate_config_payload(payload: &[u8]) -> Result<(), ConfigError> {
    let device_name =
        FixedAscii::<DEVICE_NAME_BYTES>::read_from(payload, PAYLOAD_OFFSET, PAYLOAD_OFFSET + 1)?;
    let net_mode = NetMode::from_byte(payload[57])?;
    let static_ip = read_ipv4(payload, 58)?;
    let static_netmask = read_ipv4(payload, 62)?;
    let _static_gateway = read_ipv4(payload, 66)?;
    let _static_dns = read_ipv4(payload, 70)?;
    let _buchi_ip = read_ipv4(payload, 74)?;
    let buchi_user = FixedAscii::<BUCHI_USER_BYTES>::read_from(payload, 78, 79)?;
    let buchi_password = FixedAscii::<BUCHI_PASSWORD_BYTES>::read_from(payload, 111, 112)?;
    match payload[176] {
        0 | 1 => {}
        _ => return Err(ConfigError::MalformedRecord),
    }

    validate_device_name(device_name.as_str())?;
    validate_credential(buchi_user.as_str())?;
    validate_credential(buchi_password.as_str())?;
    if matches!(net_mode, NetMode::Static) {
        if is_unspecified(static_ip) {
            return Err(ConfigError::StaticAddressRequired);
        }
        if is_unspecified(static_netmask) {
            return Err(ConfigError::StaticNetmaskRequired);
        }
        netmask_prefix_len(static_netmask)?;
    } else if !is_unspecified(static_netmask) {
        netmask_prefix_len(static_netmask)?;
    }
    Ok(())
}

fn validate_trust_payload(version: u16, payload: &[u8]) -> Result<(), ConfigError> {
    if version == LEGACY_VERSION {
        return Ok(());
    }
    read_trust_metadata(payload)?;
    Ok(())
}

fn decode_trust_payload_into(
    version: u16,
    payload: &[u8],
    trust_out: &mut GatewayTrust,
) -> Result<(), ConfigError> {
    if version == LEGACY_VERSION {
        *trust_out = GatewayTrust::missing();
        return Ok(());
    }
    let (ca_der_len, flags) = read_trust_metadata(payload)?;
    trust_out.ca_der.fill(0);
    trust_out.ca_der[..ca_der_len]
        .copy_from_slice(&payload[TRUST_CA_OFFSET..TRUST_CA_OFFSET + ca_der_len]);
    trust_out.ca_der_len = ca_der_len as u16;
    trust_out.flags = flags;
    Ok(())
}

fn read_trust_metadata(payload: &[u8]) -> Result<(usize, u16), ConfigError> {
    let ca_der_len = read_u16_le(payload, TRUST_CA_LEN_OFFSET)? as usize;
    let flags = read_u16_le(payload, TRUST_FLAGS_OFFSET)?;
    if ca_der_len > MAX_TRUST_CA_DER_BYTES {
        return Err(ConfigError::TrustCaTooLong);
    }
    if flags & !TRUST_KNOWN_FLAGS != 0 {
        return Err(ConfigError::MalformedTrust);
    }
    Ok((ca_der_len, flags))
}

pub fn encode_slot(
    sequence: u64,
    config: &GatewayConfig,
    trust: &GatewayTrust,
) -> Result<[u8; RECORD_SIZE], ConfigError> {
    encode_slot_with_kind(RecordKind::Normal, sequence, config, trust)
}

pub fn encode_reset_slot(sequence: u64, mac: [u8; 6]) -> Result<[u8; RECORD_SIZE], ConfigError> {
    encode_slot_with_kind(
        RecordKind::Reset,
        sequence,
        &GatewayConfig::defaults_from_mac(mac),
        &GatewayTrust::missing(),
    )
}

fn encode_slot_with_kind(
    kind: RecordKind,
    sequence: u64,
    config: &GatewayConfig,
    trust: &GatewayTrust,
) -> Result<[u8; RECORD_SIZE], ConfigError> {
    config.validate()?;
    trust.validate()?;
    let mut out = [0u8; RECORD_SIZE];
    write_u32_le(&mut out, 0, MAGIC);
    write_u16_le(&mut out, 4, VERSION);
    write_u16_le(&mut out, 6, RECORD_BODY_SIZE as u16);
    write_u64_le(&mut out, 8, sequence);
    encode_config_payload(&mut out, config);
    write_u16_le(&mut out, TRUST_CA_LEN_OFFSET, trust.ca_der_len);
    write_u16_le(&mut out, TRUST_FLAGS_OFFSET, trust.flags);
    out[RECORD_KIND_OFFSET] = kind as u8;
    out[TRUST_CA_OFFSET..TRUST_CA_OFFSET + trust.ca_der_len()].copy_from_slice(trust.ca_der());
    let crc = record_crc(&out, RECORD_BODY_SIZE)?;
    write_u32_le(&mut out, CRC_OFFSET, crc);
    write_u32_le(&mut out, MARKER_OFFSET, VALID_MARKER);
    Ok(out)
}

pub fn encode_legacy_slot(
    sequence: u64,
    config: &GatewayConfig,
) -> Result<[u8; LEGACY_RECORD_SIZE], ConfigError> {
    config.validate()?;
    let mut out = [0u8; LEGACY_RECORD_SIZE];
    write_u32_le(&mut out, 0, MAGIC);
    write_u16_le(&mut out, 4, LEGACY_VERSION);
    write_u16_le(&mut out, 6, LEGACY_RECORD_BODY_SIZE as u16);
    write_u64_le(&mut out, 8, sequence);
    encode_config_payload(&mut out, config);
    let crc = record_crc(&out, LEGACY_RECORD_BODY_SIZE)?;
    write_u32_le(&mut out, CRC_OFFSET, crc);
    write_u32_le(&mut out, LEGACY_MARKER_OFFSET, VALID_MARKER);
    Ok(out)
}

fn encode_config_payload(out: &mut [u8], config: &GatewayConfig) {
    config
        .device_name
        .write_to(out, PAYLOAD_OFFSET, PAYLOAD_OFFSET + 1);
    out[57] = config.net_mode.to_byte();
    write_ipv4(out, 58, config.static_ip);
    write_ipv4(out, 62, config.static_netmask);
    write_ipv4(out, 66, config.static_gateway);
    write_ipv4(out, 70, config.static_dns);
    write_ipv4(out, 74, config.buchi_ip);
    config.buchi_user.write_to(out, 78, 79);
    config.buchi_password.write_to(out, 111, 112);
    out[176] = u8::from(config.write_enable);
}

pub fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        let mut bit = 0;
        while bit < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
            bit += 1;
        }
    }
    !crc
}

fn record_crc(input: &[u8], body_len: usize) -> Result<u32, ConfigError> {
    if input.len() < body_len {
        return Err(ConfigError::MalformedRecord);
    }
    let mut crc = 0xFFFF_FFFFu32;
    let mut index = 0;
    while index < body_len {
        let byte = if (CRC_OFFSET..CRC_OFFSET + 4).contains(&index) {
            0
        } else {
            input[index]
        };
        crc ^= u32::from(byte);
        let mut bit = 0;
        while bit < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
            bit += 1;
        }
        index += 1;
    }
    Ok(!crc)
}

pub fn parse_ipv4(value: &str) -> Result<[u8; 4], ConfigError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return Err(ConfigError::InvalidIpv4);
    }
    let mut out = [0u8; 4];
    let mut part = 0usize;
    let mut acc = 0u16;
    let mut digit_count = 0u8;
    for &byte in bytes {
        if byte == b'.' {
            if digit_count == 0 || part >= 3 {
                return Err(ConfigError::InvalidIpv4);
            }
            out[part] = acc as u8;
            part += 1;
            acc = 0;
            digit_count = 0;
            continue;
        }
        if !byte.is_ascii_digit() {
            return Err(ConfigError::InvalidIpv4);
        }
        acc = acc
            .saturating_mul(10)
            .saturating_add(u16::from(byte - b'0'));
        if acc > 255 {
            return Err(ConfigError::InvalidIpv4);
        }
        digit_count = digit_count.saturating_add(1);
        if digit_count > 3 {
            return Err(ConfigError::InvalidIpv4);
        }
    }
    if digit_count == 0 || part != 3 {
        return Err(ConfigError::InvalidIpv4);
    }
    out[part] = acc as u8;
    Ok(out)
}

pub fn parse_bool(value: &str) -> Result<bool, ConfigError> {
    match value {
        "1" | "true" | "yes" | "on" | "enable" | "enabled" => Ok(true),
        "0" | "false" | "no" | "off" | "disable" | "disabled" => Ok(false),
        _ => Err(ConfigError::InvalidBool),
    }
}

pub fn netmask_prefix_len(netmask: [u8; 4]) -> Result<u8, ConfigError> {
    let value = u32::from_be_bytes(netmask);
    let mut prefix = 0u8;
    let mut seen_zero = false;
    let mut bit = 0;
    while bit < 32 {
        let set = (value & (1 << (31 - bit))) != 0;
        if set {
            if seen_zero {
                return Err(ConfigError::InvalidNetmask);
            }
            prefix += 1;
        } else {
            seen_zero = true;
        }
        bit += 1;
    }
    Ok(prefix)
}

pub const fn is_unspecified(ip: [u8; 4]) -> bool {
    ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0
}

pub struct Ipv4Display(pub [u8; 4]);

impl fmt::Display for Ipv4Display {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

impl fmt::Debug for Ipv4Display {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

fn validate_device_name(value: &str) -> Result<(), ConfigError> {
    if value.is_empty() {
        return Err(ConfigError::Empty);
    }
    if value.len() > DEVICE_NAME_BYTES || value.len() > 63 {
        return Err(ConfigError::TooLong);
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        let valid = byte.is_ascii_alphanumeric() || byte == b'-';
        if !valid {
            return Err(ConfigError::InvalidDeviceName);
        }
        index += 1;
    }
    if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
        return Err(ConfigError::InvalidDeviceName);
    }
    Ok(())
}

fn validate_credential(value: &str) -> Result<(), ConfigError> {
    if value.len() > BUCHI_PASSWORD_BYTES {
        return Err(ConfigError::TooLong);
    }
    if !value.is_ascii() {
        return Err(ConfigError::NonAscii);
    }
    for byte in value.as_bytes() {
        if !(*byte == b' ' || (0x21..=0x7e).contains(byte)) {
            return Err(ConfigError::InvalidCredential);
        }
    }
    Ok(())
}

fn write_hex_byte(out: &mut [u8], offset: usize, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out[offset] = HEX[(byte >> 4) as usize];
    out[offset + 1] = HEX[(byte & 0x0f) as usize];
}

fn read_ipv4(input: &[u8], offset: usize) -> Result<[u8; 4], ConfigError> {
    if offset + 4 > input.len() {
        return Err(ConfigError::MalformedRecord);
    }
    Ok([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}

fn write_ipv4(out: &mut [u8], offset: usize, value: [u8; 4]) {
    out[offset..offset + 4].copy_from_slice(&value);
}

fn read_u16_le(input: &[u8], offset: usize) -> Result<u16, ConfigError> {
    if offset + 2 > input.len() {
        return Err(ConfigError::MalformedRecord);
    }
    Ok(u16::from_le_bytes([input[offset], input[offset + 1]]))
}

fn read_u32_le(input: &[u8], offset: usize) -> Result<u32, ConfigError> {
    if offset + 4 > input.len() {
        return Err(ConfigError::MalformedRecord);
    }
    Ok(u32::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ]))
}

fn read_u64_le(input: &[u8], offset: usize) -> Result<u64, ConfigError> {
    if offset + 8 > input.len() {
        return Err(ConfigError::MalformedRecord);
    }
    Ok(u64::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
        input[offset + 4],
        input[offset + 5],
        input[offset + 6],
        input[offset + 7],
    ]))
}

fn write_u16_le(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_le(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64_le(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0x02, 0xa7, 0x5c, 0xe5, 0x27, 0x84];

    fn bench_config() -> GatewayConfig {
        let mut config = GatewayConfig::defaults_from_mac(MAC);
        config.set_key_value(ConfigKey::NetMode, "static").unwrap();
        config
            .set_key_value(ConfigKey::StaticIp, "192.0.2.230")
            .unwrap();
        config
            .set_key_value(ConfigKey::StaticNetmask, "255.255.0.0")
            .unwrap();
        config
            .set_key_value(ConfigKey::StaticGateway, "192.0.2.1")
            .unwrap();
        config
            .set_key_value(ConfigKey::StaticDns, "192.0.2.1")
            .unwrap();
        config
            .set_key_value(ConfigKey::BuchiIp, "192.0.2.1")
            .unwrap();
        config.set_key_value(ConfigKey::BuchiUser, "rw").unwrap();
        config
            .set_key_value(ConfigKey::BuchiPassword, "secret")
            .unwrap();
        config
            .set_key_value(ConfigKey::WriteEnable, "true")
            .unwrap();
        config
    }

    #[test]
    fn uid_defaults_apply_only_to_blank_storage_or_reset_tombstones() {
        let defaults = GatewayConfig::defaults_from_uid([0x00210029, 0x3432510d, 0x31383339]);
        let erased = [0xff; RECORD_SIZE];
        let mut trust = GatewayTrust::missing();
        assert_eq!(
            select_config_into(&erased, &erased, defaults, &mut trust).1,
            defaults
        );
        let stored = GatewayConfig::defaults_from_mac(MAC);
        let normal = encode_slot(7, &stored, &trust).unwrap();
        assert_eq!(
            select_config_into(&normal, &erased, defaults, &mut trust).1,
            stored
        );
        let reset = encode_reset_slot(8, MAC).unwrap();
        let (status, selected) = select_config_into(&normal, &reset, defaults, &mut trust);
        assert_eq!(status.kind, Some(RecordKind::Reset));
        assert_eq!(selected, defaults);
        // Legacy decoding and raw tombstone representation remain compatible.
        assert_eq!(select_config(&normal, &reset, MAC).config, stored);
    }

    #[test]
    fn uid_defaults_use_every_word_and_preserve_other_defaults() {
        let first = GatewayConfig::defaults_from_uid([0x00210029, 0x3432510d, 0x31383339]);
        assert_eq!(first.device_name.as_str(), "opta-002100293432510d31383339");
        assert_eq!(first.device_name.as_str().len(), 29);
        first.validate().unwrap();
        for index in 0..3 {
            let mut uid = [0x00210029, 0x3432510d, 0x31383339];
            uid[index] ^= 1;
            assert_ne!(
                first.device_name,
                GatewayConfig::defaults_from_uid(uid).device_name
            );
        }
        let mut other = GatewayConfig::defaults_from_uid([u32::MAX; 3]);
        assert_eq!(other.device_name.as_str(), "opta-ffffffffffffffffffffffff");
        other.device_name = first.device_name;
        assert_eq!(first, other);
    }

    #[test]
    fn trust_state_wire_values_cover_all_policy_states() {
        for state in [
            TrustState::Missing,
            TrustState::Provisioned,
            TrustState::Verified,
            TrustState::VerifyRejected,
            TrustState::Revoked,
        ] {
            assert_eq!(TrustState::from_u32(state as u32), Some(state));
        }
        assert_eq!(TrustState::from_u32(5), None);
    }

    #[test]
    fn crc32_ieee_known_vector() {
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn erased_slots_fall_back_to_mac_defaults() {
        let erased = [0xFFu8; RECORD_SIZE];
        let loaded = select_config(&erased, &erased, MAC);
        assert_eq!(loaded.source, ConfigSource::Defaults);
        assert_eq!(loaded.sequence, 0);
        assert_eq!(loaded.config.device_name.as_str(), "opta-gw-2784");
        assert_eq!(loaded.config.net_mode, NetMode::Dhcp);
    }

    #[test]
    fn corrupt_slot_is_ignored() {
        let config = bench_config();
        let mut slot = encode_slot(7, &config, &GatewayTrust::missing()).unwrap();
        slot[40] ^= 0x55;
        let erased = [0xFFu8; RECORD_SIZE];
        let loaded = select_config(&slot, &erased, MAC);
        assert_eq!(loaded.source, ConfigSource::Defaults);
        assert_eq!(loaded.slot_a.error, Some(ConfigError::CrcMismatch));
    }

    #[test]
    fn partial_write_without_marker_is_invalid() {
        let config = bench_config();
        let mut slot = encode_slot(1, &config, &GatewayTrust::missing()).unwrap();
        slot[MARKER_OFFSET..RECORD_SIZE].fill(0xFF);
        let decoded = decode_slot(&slot, GatewayConfig::defaults_from_mac(MAC));
        assert!(!decoded.valid);
        assert_eq!(decoded.error, Some(ConfigError::MissingValidMarker));
    }

    #[test]
    fn newest_valid_sequence_wins() {
        let mut older = bench_config();
        older
            .set_key_value(ConfigKey::DeviceName, "opta-old")
            .unwrap();
        let mut newer = bench_config();
        newer
            .set_key_value(ConfigKey::DeviceName, "opta-new")
            .unwrap();
        let slot_a = encode_slot(10, &older, &GatewayTrust::missing()).unwrap();
        let slot_b = encode_slot(11, &newer, &GatewayTrust::missing()).unwrap();
        let loaded = select_config(&slot_a, &slot_b, MAC);
        assert_eq!(loaded.source, ConfigSource::SlotB);
        assert_eq!(loaded.sequence, 11);
        assert_eq!(loaded.config.device_name.as_str(), "opta-new");
        assert_eq!(loaded.inactive_slot(), ConfigSource::SlotA);
        assert_eq!(loaded.next_sequence(), 12);
    }

    #[test]
    fn validation_rejects_bad_static_netmask_and_name() {
        let mut config = bench_config();
        assert!(config.set_key_value(ConfigKey::DeviceName, "-bad").is_err());
        assert!(config
            .set_key_value(ConfigKey::StaticNetmask, "255.0.255.0")
            .is_err());
    }

    #[test]
    fn key_setters_validate_values() {
        let mut config = GatewayConfig::defaults_from_mac(MAC);
        config.set_key_value(ConfigKey::NetMode, "static").unwrap();
        assert_eq!(
            config.set_key_value(ConfigKey::StaticIp, "300.1.1.1"),
            Err(ConfigError::InvalidIpv4)
        );
        assert_eq!(
            ConfigKey::parse("buchi-password").unwrap(),
            ConfigKey::BuchiPassword
        );
        assert_eq!(ConfigKey::parse("unknown"), Err(ConfigError::UnknownKey));
        assert_eq!(parse_bool("enabled"), Ok(true));
        assert_eq!(parse_bool("disabled"), Ok(false));
    }

    #[test]
    fn password_redaction_state_only() {
        let mut config = GatewayConfig::defaults_from_mac(MAC);
        assert_eq!(config.password_state(), PasswordState::Missing);
        config
            .set_key_value(ConfigKey::BuchiPassword, "secret")
            .unwrap();
        assert_eq!(config.password_state(), PasswordState::Set);
        let debug = format!("{:?}", config);
        assert!(debug.contains("set"));
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn record_round_trip_preserves_config() {
        let config = bench_config();
        let trust = GatewayTrust::from_ca_der(&[0x30, 0x03, 0x02, 0x01, 0x00], true).unwrap();
        let slot = encode_slot(42, &config, &trust).unwrap();
        assert_eq!(slot.len(), RECORD_SIZE);
        assert_eq!(
            u32::from_le_bytes(slot[MARKER_OFFSET..MARKER_OFFSET + 4].try_into().unwrap()),
            VALID_MARKER
        );
        let decoded = decode_slot(&slot, GatewayConfig::defaults_from_mac(MAC));
        assert!(decoded.valid);
        assert_eq!(decoded.version, VERSION);
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.config, config);
        assert_eq!(decoded.trust, trust);
    }

    #[test]
    fn legacy_record_decodes_with_missing_trust() {
        let config = bench_config();
        let legacy = encode_legacy_slot(9, &config).unwrap();
        let decoded = decode_slot(&legacy, GatewayConfig::defaults_from_mac(MAC));
        assert!(decoded.valid);
        assert_eq!(decoded.version, LEGACY_VERSION);
        assert_eq!(decoded.sequence, 9);
        assert_eq!(decoded.config, config);
        assert_eq!(decoded.trust, GatewayTrust::missing());
    }

    #[test]
    fn newer_legacy_record_wins_without_synthesizing_trust() {
        let config = bench_config();
        let v2_trust = GatewayTrust::from_ca_der(&[1, 2, 3], true).unwrap();
        let v2 = encode_slot(10, &config, &v2_trust).unwrap();
        let legacy = encode_legacy_slot(11, &config).unwrap();
        let loaded = select_config(&v2, &legacy, MAC);
        assert_eq!(loaded.source, ConfigSource::SlotB);
        assert_eq!(loaded.version, LEGACY_VERSION);
        assert_eq!(loaded.sequence, 11);
        assert_eq!(loaded.trust, GatewayTrust::missing());
    }

    #[test]
    fn trust_is_bounded_and_either_commissioning_step_alone_is_incomplete() {
        let oversized = [0x55; MAX_TRUST_CA_DER_BYTES + 1];
        assert_eq!(
            GatewayTrust::from_ca_der(&oversized, true),
            Err(ConfigError::TrustCaTooLong)
        );
        let time_only = GatewayTrust::from_ca_der(&[], true).unwrap();
        assert!(time_only.time_provisioned());
        assert!(!time_only.is_anchor_present());
        assert!(!time_only.is_complete());

        let ca_only = GatewayTrust::from_ca_der(&[1, 2, 3], false).unwrap();
        assert!(!ca_only.time_provisioned());
        assert!(ca_only.is_anchor_present());
        assert!(!ca_only.is_complete());
    }

    #[test]
    fn ca_replacement_preserves_false_and_true_time_markers_in_persisted_records() {
        let config = bench_config();
        for (sequence, marker) in [(50, false), (51, true)] {
            let mut trust = GatewayTrust::from_ca_der(&[1, 2, 3], marker).unwrap();
            trust.replace_ca_der(&[4, 5, 6, 7]).unwrap();
            assert_eq!(trust.ca_der(), &[4, 5, 6, 7]);
            assert_eq!(trust.time_provisioned(), marker);
            assert_eq!(trust.is_complete(), marker);

            let record = encode_slot(sequence, &config, &trust).unwrap();
            let decoded = decode_slot(&record, GatewayConfig::defaults_from_mac(MAC));
            assert!(decoded.valid);
            assert_eq!(decoded.trust.ca_der(), &[4, 5, 6, 7]);
            assert_eq!(decoded.trust.time_provisioned(), marker);
            assert_eq!(decoded.trust.is_complete(), marker);
        }
    }

    #[test]
    fn failed_ca_replacement_leaves_existing_material_and_marker_unchanged() {
        let mut trust = GatewayTrust::from_ca_der(&[1, 2, 3], true).unwrap();
        let before = trust.clone();
        let oversized = [0x55; MAX_TRUST_CA_DER_BYTES + 1];
        assert_eq!(
            trust.replace_ca_der(&oversized),
            Err(ConfigError::TrustCaTooLong)
        );
        assert_eq!(trust, before);
    }

    #[test]
    fn trust_bytes_are_covered_by_record_crc() {
        let config = bench_config();
        let trust = GatewayTrust::from_ca_der(&[0x30, 0x01, 0x00], true).unwrap();
        let mut slot = encode_slot(3, &config, &trust).unwrap();
        slot[TRUST_CA_OFFSET + 1] ^= 0x01;
        let decoded = decode_slot(&slot, GatewayConfig::defaults_from_mac(MAC));
        assert!(!decoded.valid);
        assert_eq!(decoded.error, Some(ConfigError::CrcMismatch));
    }

    #[test]
    fn chunked_trust_upload_is_sequential_bounded_and_zeroizable() {
        let mut upload = TrustUpload::new();
        assert_eq!(upload.append_hex("00"), Err(TrustUploadError::NotStarted));
        assert_eq!(upload.begin(0), Err(TrustUploadError::InvalidLength));
        upload.begin(5).unwrap();
        assert_eq!(upload.append_hex("300302"), Ok(3));
        assert_eq!(upload.received_len(), 3);
        assert_eq!(upload.ca_der(), Err(TrustUploadError::Incomplete));
        assert_eq!(upload.append_hex("0100"), Ok(2));
        assert_eq!(upload.ca_der().unwrap(), &[0x30, 0x03, 0x02, 0x01, 0x00]);
        upload.reset();
        assert_eq!(upload.ca_der(), Err(TrustUploadError::NotStarted));
    }

    #[test]
    fn chunked_trust_upload_rejects_bad_hex_and_overrun() {
        let mut upload = TrustUpload::new();
        upload.begin(2).unwrap();
        assert_eq!(upload.append_hex("0"), Err(TrustUploadError::OddHexLength));
        assert_eq!(upload.append_hex("0x"), Err(TrustUploadError::InvalidHex));
        assert_eq!(upload.received_len(), 0);
        assert_eq!(
            upload.append_hex("000102"),
            Err(TrustUploadError::ExceedsDeclaredLength)
        );
    }

    #[test]
    fn trust_unix_time_round_trips_rtc_calendar_bounds() {
        for seconds in [
            MIN_TRUST_UNIX_SECONDS,
            1_782_388_800,
            1_832_803_199,
            MAX_TRUST_UNIX_SECONDS,
        ] {
            let datetime = unix_seconds_to_utc(seconds).unwrap();
            assert_eq!(utc_to_unix_seconds(datetime), Ok(seconds));
        }
        assert_eq!(
            unix_seconds_to_utc(MIN_TRUST_UNIX_SECONDS - 1),
            Err(ConfigError::MalformedTrust)
        );
        assert_eq!(
            unix_seconds_to_utc(MAX_TRUST_UNIX_SECONDS + 1),
            Err(ConfigError::MalformedTrust)
        );
    }
}
