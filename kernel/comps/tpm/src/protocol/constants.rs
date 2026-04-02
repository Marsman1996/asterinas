// SPDX-License-Identifier: MPL-2.0

//! TPM 2.0 protocol constants.

/// TPM 2.0 command tags.
pub mod tag {
    /// Command with no session.
    pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
    /// Command with session.
    pub const TPM_ST_SESSIONS: u16 = 0x8002;
    /// Response with no session.
    pub const TPM_ST_RSP_NO_SESSIONS: u16 = 0x8001;
    /// Response with session.
    pub const TPM_ST_RSP_SESSIONS: u16 = 0x8002;
}

/// TPM 2.0 command codes.
pub mod command {
    /// TPM2_Startup command code.
    pub const TPM2_STARTUP: u32 = 0x00000144;
    /// TPM2_GetCapability command code.
    pub const TPM2_GET_CAPABILITY: u32 = 0x0000017A;
    /// TPM2_GetRandom command code.
    pub const TPM2_GET_RANDOM: u32 = 0x0000017B;
    /// TPM2_PCR_Read command code.
    pub const TPM2_PCR_READ: u32 = 0x0000017E;
    /// TPM2_StartAuthSession command code.
    pub const TPM2_START_AUTH_SESSION: u32 = 0x00000176;
    /// TPM2_FlushContext command code.
    pub const TPM2_FLUSH_CONTEXT: u32 = 0x00000165;
    /// TPM2_PolicyPCR command code.
    pub const TPM2_POLICY_PCR: u32 = 0x0000017F;
    /// TPM2_PolicyGetDigest command code.
    pub const TPM2_POLICY_GET_DIGEST: u32 = 0x00000189;
    /// TPM2_NV_ReadPublic command code.
    pub const TPM2_NV_READ_PUBLIC: u32 = 0x00000169;
    /// TPM2_NV_Read command code.
    pub const TPM2_NV_READ: u32 = 0x0000014E;
    /// TPM2_NV_Write command code.
    pub const TPM2_NV_WRITE: u32 = 0x00000137;
    /// TPM2_NV_DefineSpace command code.
    pub const TPM2_NV_DEFINE_SPACE: u32 = 0x0000012A;
    /// TPM2_ContextSave command code.
    pub const TPM2_CONTEXT_SAVE: u32 = 0x00000162;
    /// TPM2_ContextLoad command code.
    pub const TPM2_CONTEXT_LOAD: u32 = 0x00000161;
}

/// TPM 2.0 capability types.
pub mod capability {
    /// TPM properties.
    pub const TPM_CAP_TPM_PROPERTIES: u32 = 0x00000006;
    /// PCR properties.
    pub const TPM_CAP_PCR_PROPERTIES: u32 = 0x00000005;
}

/// TPM 2.0 property tags.
pub mod property {
    /// Manufacturer property.
    pub const TPM_PT_MANUFACTURER: u32 = 0x00000105;
    /// Firmware version 1.
    pub const TPM_PT_FIRMWARE_VERSION_1: u32 = 0x00000106;
    /// Firmware version 2.
    pub const TPM_PT_FIRMWARE_VERSION_2: u32 = 0x00000107;
}

/// TPM 2.0 response codes.
pub mod rc {
    /// Success.
    pub const TPM_RC_SUCCESS: u32 = 0x00000000;
    /// Bad tag.
    pub const TPM_RC_BAD_TAG: u32 = 0x000001E0;
    /// Value is out of range or is not correct for the context.
    pub const TPM_RC_VALUE: u32 = 0x00000004;
}

/// TPM 2.0 startup types.
pub mod startup {
    /// Clear startup.
    pub const TPM_SU_CLEAR: u16 = 0x0000;
    /// State save startup.
    pub const TPM_SU_STATE: u16 = 0x0001;
}

/// TPM 2.0 GetRandom constants.
pub mod random {
    /// Maximum bytes per GetRandom call.
    pub const TPM_MAX_RANDOM_BYTES: usize = 64;
}

/// TPM 2.0 PCR constants.
pub mod pcr {
    /// SHA-1 bank algorithm ID.
    pub const TPM_ALG_SHA1: u16 = 0x0004;
    /// SHA-256 bank algorithm ID.
    pub const TPM_ALG_SHA256: u16 = 0x000B;
    /// SHA-384 bank algorithm ID.
    pub const TPM_ALG_SHA384: u16 = 0x000C;
    /// SHA-512 bank algorithm ID.
    pub const TPM_ALG_SHA512: u16 = 0x000D;
    /// Maximum number of PCRs (typically 24).
    pub const TPM_MAX_PCRS: u32 = 24;
    /// Size of SHA-256 digest.
    pub const SHA256_DIGEST_SIZE: usize = 32;
}

/// TPM 2.0 session types.
pub mod session {
    /// Password authorization session handle.
    pub const TPM_RS_PW: u32 = 0x40000009;
    /// HMAC session type.
    pub const TPM_SE_HMAC: u8 = 0x00;
    /// Policy session type.
    pub const TPM_SE_POLICY: u8 = 0x01;
    /// Trial policy session type.
    pub const TPM_SE_TRIAL: u8 = 0x03;
}

/// TPM 2.0 handle ranges.
pub mod handle {
    /// Session handle range start.
    pub const TPM_HT_HMAC_SESSION: u32 = 0x02000000;
    /// Policy session handle range start.
    pub const TPM_HT_POLICY_SESSION: u32 = 0x03000000;
    /// Permanent handle range start.
    pub const TPM_HT_PERMANENT: u32 = 0x40000000;
}

/// TPM 2.0 algorithm constants.
pub mod alg {
    /// Null algorithm.
    pub const TPM_ALG_NULL: u16 = 0x0010;
}
