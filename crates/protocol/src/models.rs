//! LocalSend v2 Protocol Wire Models & Schemas
//!
//! Strongly typed serde data structures adhering to the LocalSend v2.0/v2.1 specification.

use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const DEFAULT_PORT: u16 = 53317;

const fn default_port() -> u16 {
    DEFAULT_PORT
}

const fn default_true() -> bool {
    true
}

/// Device categories recognized in LocalSend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    /// Mobile phones and tablets.
    Mobile,
    /// Desktop computers and laptops.
    Desktop,
    /// Web browser clients.
    Web,
    /// Headless daemon / service installations.
    Headless,
    /// Dedicated servers.
    Server,
}

impl Default for DeviceType {
    fn default() -> Self {
        Self::Desktop
    }
}

impl<'de> Deserialize<'de> for DeviceType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DeviceTypeVisitor;

        impl Visitor<'_> for DeviceTypeVisitor {
            type Value = DeviceType;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string representing a DeviceType")
            }

            fn visit_str<E>(self, value: &str) -> Result<DeviceType, E>
            where
                E: de::Error,
            {
                match value.to_ascii_lowercase().as_str() {
                    "mobile" => Ok(DeviceType::Mobile),
                    "desktop" => Ok(DeviceType::Desktop),
                    "web" => Ok(DeviceType::Web),
                    "headless" => Ok(DeviceType::Headless),
                    "server" => Ok(DeviceType::Server),
                    // Robust fallback for unknown third-party values
                    _ => Ok(DeviceType::Desktop),
                }
            }

            fn visit_string<E>(self, value: String) -> Result<DeviceType, E>
            where
                E: de::Error,
            {
                self.visit_str(&value)
            }
        }

        deserializer.deserialize_str(DeviceTypeVisitor)
    }
}

/// Network transport protocol variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolType {
    /// Insecure plain HTTP.
    Http,
    /// Encrypted HTTPS with self-signed TLS.
    Https,
}

impl Default for ProtocolType {
    fn default() -> Self {
        Self::Https
    }
}

impl std::fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http => write!(f, "http"),
            Self::Https => write!(f, "https"),
        }
    }
}

/// Payload broadcasted over UDP multicast (224.0.0.167:53317).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MulticastAnnouncement {
    /// Human-friendly peer alias.
    pub alias: String,
    /// Protocol version string (must be "2.0").
    pub version: String,
    /// Hardware/device model name.
    #[serde(rename = "deviceModel", skip_serializing_if = "Option::is_none")]
    pub device_model: Option<String>,
    /// Device category.
    #[serde(rename = "deviceType", skip_serializing_if = "Option::is_none")]
    pub device_type: Option<DeviceType>,
    /// SHA-256 certificate fingerprint (HTTPS) or random token (HTTP).
    pub fingerprint: String,
    /// Listening TCP port.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Transport protocol.
    pub protocol: ProtocolType,
    /// Whether peer is willing to receive files.
    pub download: bool,
    /// Whether this is an announcement packet.
    #[serde(alias = "announcement", default = "default_true")]
    pub announce: bool,
}

impl MulticastAnnouncement {
    /// Construct a new multicast announcement with standard defaults.
    pub fn new(
        alias: impl Into<String>,
        fingerprint: impl Into<String>,
        port: u16,
        protocol: ProtocolType,
    ) -> Self {
        Self {
            alias: alias.into(),
            version: "2.0".to_string(),
            device_model: None,
            device_type: Some(DeviceType::Headless),
            fingerprint: fingerprint.into(),
            port,
            protocol,
            download: true,
            announce: true,
        }
    }

    /// Validate that the protocol version is supported.
    pub fn is_compatible_version(&self) -> bool {
        self.version == "2.0"
    }
}

/// Direct peer registration payload for `POST /api/localsend/v2/register`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterDto {
    /// Human-friendly peer alias.
    pub alias: String,
    /// Protocol version string.
    pub version: String,
    /// Hardware/device model name.
    #[serde(rename = "deviceModel", skip_serializing_if = "Option::is_none")]
    pub device_model: Option<String>,
    /// Device category.
    #[serde(rename = "deviceType", skip_serializing_if = "Option::is_none")]
    pub device_type: Option<DeviceType>,
    /// Certificate fingerprint.
    pub fingerprint: String,
    /// Listening port.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Transport protocol.
    pub protocol: ProtocolType,
    /// Whether peer is willing to download files.
    pub download: bool,
}

impl From<MulticastAnnouncement> for RegisterDto {
    fn from(ann: MulticastAnnouncement) -> Self {
        Self {
            alias: ann.alias,
            version: ann.version,
            device_model: ann.device_model,
            device_type: ann.device_type,
            fingerprint: ann.fingerprint,
            port: ann.port,
            protocol: ann.protocol,
            download: ann.download,
        }
    }
}

/// Metadata describing an individual file to be transferred.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileMetadata {
    /// Unique identifier for the file within the session.
    pub id: String,
    /// Original file name.
    #[serde(rename = "fileName")]
    pub file_name: String,
    /// Size of the file in bytes.
    pub size: u64,
    /// MIME type or custom file type indicator.
    #[serde(rename = "fileType")]
    pub file_type: String,
    /// Optional SHA-256 digest of file contents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Optional preview image or text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
    /// Optional arbitrary metadata dictionary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Request body for `POST /api/localsend/v2/prepare-upload`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrepareUploadRequest {
    /// Sender's registration information.
    pub info: RegisterDto,
    /// Mapping of file ID to file metadata.
    pub files: HashMap<String, FileMetadata>,
}

/// Response returned from `POST /api/localsend/v2/prepare-upload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepareUploadResponse {
    /// Assigned transfer session identifier.
    #[serde(rename = "sessionId")]
    pub session_id: String,
    /// Mapping of file ID to secret upload token.
    pub files: HashMap<String, String>,
}

/// Query parameters for `POST /api/localsend/v2/upload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadParams {
    /// Transfer session identifier.
    #[serde(rename = "sessionId")]
    pub session_id: String,
    /// Specific file identifier being uploaded.
    #[serde(rename = "fileId")]
    pub file_id: String,
    /// Secret authentication token granted for this file.
    pub token: String,
}

/// Device info response for `GET /api/localsend/v2/info`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfoResponseDto {
    /// Human-friendly peer alias.
    pub alias: String,
    /// Protocol version string.
    pub version: String,
    /// Hardware/device model name.
    #[serde(rename = "deviceModel", skip_serializing_if = "Option::is_none")]
    pub device_model: Option<String>,
    /// Device category.
    #[serde(rename = "deviceType", skip_serializing_if = "Option::is_none")]
    pub device_type: Option<DeviceType>,
    /// Certificate fingerprint.
    pub fingerprint: String,
    /// Listening port.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Transport protocol.
    pub protocol: ProtocolType,
    /// Whether peer accepts downloads.
    pub download: bool,
}

impl From<RegisterDto> for InfoResponseDto {
    fn from(reg: RegisterDto) -> Self {
        Self {
            alias: reg.alias,
            version: reg.version,
            device_model: reg.device_model,
            device_type: reg.device_type,
            fingerprint: reg.fingerprint,
            port: reg.port,
            protocol: reg.protocol,
            download: reg.download,
        }
    }
}
