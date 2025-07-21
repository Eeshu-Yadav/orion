// SPDX-FileCopyrightText: © 2025 Huawei Cloud Computing Technologies Co., Ltd
// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025 Huawei Cloud Computing Technologies Co., Ltd
//
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//

use super::secret::{TlsCertificate, ValidationContext};
use crate::config::common::*;
use base64::Engine as _;
use compact_str::CompactString;
use serde::{
    de::{self, MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Serialize,
};
use std::{
    ffi::{CStr, CString},
    str::FromStr,
};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct BindDevice {
    /// A interface name as defined by linux SO_BINDTODEVICE
    interface: CString,
}

impl BindDevice {
    pub fn interface(&self) -> &CStr {
        &self.interface
    }
}

impl Serialize for BindDevice {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut serializer = serializer.serialize_struct("bind_device", 1)?;
        if let Ok(interface) = self.interface.to_str() {
            // we might want to loosen this restriction to allow non-ascii alphanumeric.
            // but we should always deny any char that has to be escaped to print in utf8
            if interface.chars().all(|c| c.is_ascii_alphanumeric()) {
                serializer.serialize_field("interface", &interface)?;
                return serializer.end();
            }
        }
        let iface_bytes = self.interface.to_bytes();
        let bytes = base64::engine::general_purpose::STANDARD.encode(iface_bytes);
        serializer.serialize_field("interface_bytes", &bytes)?;
        serializer.end()
    }
}

impl<'de> Deserialize<'de> for BindDevice {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Interface,
            InterfaceBytes,
        }

        struct StructVisitor;

        impl<'de> Visitor<'de> for StructVisitor {
            type Value = BindDevice;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct BindDevice")
            }

            fn visit_map<V>(self, mut map: V) -> Result<BindDevice, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut bytes = None;
                while let Some(key) = map.next_key()? {
                    let string: String = map.next_value()?;
                    match key {
                        Field::Interface => {
                            if bytes.is_some() {
                                return Err(de::Error::duplicate_field("interface OR interface_bytes"));
                            }
                            bytes = Some(string.into_bytes());
                        },
                        Field::InterfaceBytes => {
                            if bytes.is_some() {
                                return Err(de::Error::duplicate_field("interface OR interface_bytes"));
                            }
                            bytes = Some(base64::engine::general_purpose::STANDARD.decode(&string).map_err(|e| {
                                de::Error::custom(format!("failed to decode interface_bytes as base64: {e}"))
                            })?);
                        },
                    }
                }
                let bytes = bytes.ok_or_else(|| de::Error::missing_field("interface OR interface_bytes"))?;

                BindDevice::try_from(bytes)
                    .map_err(|e| de::Error::custom(format!("failed to parse bind_interface: {e}")))
            }
        }

        const FIELDS: &[&str] = &["interface", "interface_bytes"];
        deserializer.deserialize_struct("BindDevice", FIELDS, StructVisitor)
    }
}

impl FromStr for BindDevice {
    type Err = GenericError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.as_bytes().to_vec().try_into()
    }
}

impl TryFrom<Vec<u8>> for BindDevice {
    type Error = GenericError;
    fn try_from(mut value: Vec<u8>) -> Result<Self, Self::Error> {
        const IFNAMSIZE: usize = 16;
        if value.last() != Some(&0u8) {
            // Append NULL if missing
            value.push(0);
        }

        let interface = std::ffi::CString::from_vec_with_nul(value)
            .map_err(|e| GenericError::from_msg_with_cause("failed to conver interface to CString", e))?;
        if interface.as_bytes_with_nul().len() > IFNAMSIZE {
            Err(GenericError::from_msg(format!(
                "invalid interface name {}. Maximum length ({IFNAMSIZE}) exceeded",
                interface.to_string_lossy()
            )))
        } else {
            Ok(Self { interface })
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommonTlsContext {
    #[serde(skip_serializing_if = "is_default", default)]
    pub parameters: TlsParameters,
    #[serde(flatten)]
    pub secrets: Secrets,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none", default = "Default::default")]
    pub validation_context: Option<CommonTlsValidationContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsParameters {
    #[serde(skip_serializing_if = "is_default_min_tls_version", default = "default_min_tls_version")]
    pub minimum_protocol_version: TlsVersion,
    #[serde(skip_serializing_if = "Option::is_none", default = "Default::default")]
    pub maximum_protocol_version: Option<TlsVersion>,
}

fn default_min_tls_version() -> TlsVersion {
    TlsVersion::TLSv1_2
}

fn is_default_min_tls_version(value: &TlsVersion) -> bool {
    *value == default_min_tls_version()
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TlsVersion {
    TLSv1_2,
    TLSv1_3,
}

impl TlsParameters {
    pub fn supported_version(&self) -> &'static [TlsVersion] {
        match self.minimum_protocol_version {
            // assume that minimum <= maximum
            TlsVersion::TLSv1_3 => &[TlsVersion::TLSv1_3],
            TlsVersion::TLSv1_2 => match self.maximum_protocol_version {
                None | Some(TlsVersion::TLSv1_3) => &[TlsVersion::TLSv1_2, TlsVersion::TLSv1_3],
                Some(TlsVersion::TLSv1_2) => &[TlsVersion::TLSv1_2],
            },
        }
    }
}

impl Default for TlsParameters {
    fn default() -> Self {
        Self { maximum_protocol_version: None, minimum_protocol_version: TlsVersion::TLSv1_2 }
    }
}

pub struct SdsConfig {
    pub name: CompactString,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Secrets {
    #[serde(rename = "tls_certificates_sds")]
    SdsConfig(Vec<CompactString>),
    #[serde(rename = "tls_certificates")]
    Certificates(Vec<TlsCertificate>),
}

impl Secrets {
    pub fn len(&self) -> usize {
        match self {
            Self::Certificates(v) => v.len(),
            Self::SdsConfig(v) => v.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl From<Vec<SdsConfig>> for Secrets {
    fn from(value: Vec<SdsConfig>) -> Self {
        Self::SdsConfig(value.into_iter().map(|x| x.name).collect())
    }
}

impl From<Vec<TlsCertificate>> for Secrets {
    fn from(value: Vec<TlsCertificate>) -> Self {
        Self::Certificates(value)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CommonTlsValidationContext {
    #[serde(rename = "validation_context_sds")]
    SdsConfig(CompactString),
    ValidationContext(ValidationContext),
}

#[cfg(feature = "envoy-conversions")]
pub(crate) use envoy_conversions::*;
#[cfg(feature = "envoy-conversions")]
mod envoy_conversions {
    #![allow(deprecated)]
    use super::{
        BindDevice, CommonTlsContext, CommonTlsValidationContext, SdsConfig, Secrets, TlsCertificate, TlsParameters,
        TlsVersion,
    };
    use crate::config::common::*;
    use compact_str::CompactString;
    use orion_data_plane_api::envoy_data_plane_api::{
        envoy::{
            config::core::v3::{socket_option::Value as EnvoySocketOptionValue, SocketOption as EnvoySocketOption},
            extensions::transport_sockets::tls::v3::{
                common_tls_context::ValidationContextType as EnvoyValidationContextType,
                tls_parameters::TlsProtocol as EnvoyTlsProtocol, CommonTlsContext as EnvoyCommonTlsContext,
                DownstreamTlsContext as EnvoyDownstreamTlsContext, SdsSecretConfig as EnvoySdsSecretConfig,
                TlsParameters as EnvoyTlsParameters, UpstreamTlsContext as EnvoyUpstreamTlsContext,
            },
        },
        google::protobuf::Any,
        prost::Message,
    };

    impl BindDevice {
        const fn socket_option() -> (i64, i64) {
            (1, 25)
        }
    }

    impl TryFrom<EnvoySocketOption> for BindDevice {
        type Error = GenericError;
        fn try_from(value: EnvoySocketOption) -> Result<Self, Self::Error> {
            let EnvoySocketOption { description, level, name, state, value, r#type: _ } = value;
            unsupported_field!(state)?;
            // this field is
            // > An optional name to give this socket option for debugging, etc.
            // > Uniqueness is not required and no special meaning is assumed.
            // so while we don't use it, there should be no harm in allowing it.
            let _ = description;
            if (level, name) == BindDevice::socket_option() {
                // max interface name w/NULL (see net/if.h)

                match required!(value)? {
                    EnvoySocketOptionValue::BufValue(name) => name.try_into(),
                    EnvoySocketOptionValue::IntValue(_) => Err(GenericError::unsupported_variant("IntValue")),
                }
                .with_node("value")
            } else {
                Err(GenericError::from_msg(format!(
                    "unsupported level/name pair \"({level}, {name})\". Only BindDevice \"{:?}\" is supported.",
                    Self::socket_option()
                )))
            }
        }
    }

    impl TryFrom<EnvoyTlsParameters> for TlsParameters {
        type Error = GenericError;
        fn try_from(value: EnvoyTlsParameters) -> Result<Self, Self::Error> {
            let EnvoyTlsParameters {
                tls_minimum_protocol_version,
                tls_maximum_protocol_version,
                cipher_suites,
                ecdh_curves,
                signature_algorithms,
                compliance_policies,
            } = value;
            unsupported_field!(
                // tls_minimum_protocol_version,
                // tls_maximum_protocol_version,
                cipher_suites,
                ecdh_curves,
                signature_algorithms,
                compliance_policies
            )?;

            let tls_minimum_protocol_version = EnvoyTlsProtocol::from_i32(tls_minimum_protocol_version)
                .ok_or_else(|| {
                    GenericError::unsupported_variant(format!(
                        "[unknown tls protocol variant {tls_minimum_protocol_version}]"
                    ))
                })
                .with_node("tls_minimum_protocol_version")?;
            let minimum_protocol_version = match tls_minimum_protocol_version {
                EnvoyTlsProtocol::TlsAuto | EnvoyTlsProtocol::TlSv12 => TlsVersion::TLSv1_2,
                EnvoyTlsProtocol::TlSv13 => TlsVersion::TLSv1_3,
                EnvoyTlsProtocol::TlSv10 | EnvoyTlsProtocol::TlSv11 => {
                    return Err(GenericError::from_msg("TLS 1.2 is the minimum supported version"))
                        .with_node("tls_minimum_protocol_version")
                },
            };
            let tls_maximum_protocol_version = EnvoyTlsProtocol::from_i32(tls_maximum_protocol_version)
                .ok_or_else(|| {
                    GenericError::unsupported_variant(format!(
                        "[unknown tls protocol variant {tls_maximum_protocol_version}]"
                    ))
                })
                .with_node("tls_maximum_protocol_version")?;
            let maximum_protocol_version = match tls_maximum_protocol_version {
                // if auto just don't set a maximum, in case TLSv1_4 is ever added
                EnvoyTlsProtocol::TlsAuto => None,
                EnvoyTlsProtocol::TlSv13 => Some(TlsVersion::TLSv1_3),
                EnvoyTlsProtocol::TlSv12 => Some(TlsVersion::TLSv1_2),
                EnvoyTlsProtocol::TlSv10 | EnvoyTlsProtocol::TlSv11 => {
                    return Err(GenericError::from_msg("TLS 1.2 is the minimum supported version"))
                        .with_node("tls_maximum_protocol_version")
                },
            };
            if matches!(
                (minimum_protocol_version, maximum_protocol_version),
                (TlsVersion::TLSv1_3, Some(TlsVersion::TLSv1_2))
            ) {
                return Err(GenericError::from_msg("minimum TLS version is newer than maximum TLS version"));
            }
            Ok(Self { minimum_protocol_version, maximum_protocol_version })
        }
    }

    impl TryFrom<EnvoyCommonTlsContext> for CommonTlsContext {
        type Error = GenericError;
        fn try_from(value: EnvoyCommonTlsContext) -> Result<Self, Self::Error> {
            let EnvoyCommonTlsContext {
                tls_params,
                tls_certificates,
                tls_certificate_sds_secret_configs,
                tls_certificate_provider_instance,
                tls_certificate_certificate_provider,
                tls_certificate_certificate_provider_instance,
                alpn_protocols,
                custom_handshaker,
                key_log,
                validation_context_type,
                custom_tls_certificate_selector,
            } = value;
            unsupported_field!(
                // tls_params,
                // tls_certificates,
                // tls_certificate_sds_secret_configs,
                tls_certificate_provider_instance,
                tls_certificate_certificate_provider,
                tls_certificate_certificate_provider_instance,
                alpn_protocols,
                custom_handshaker,
                key_log, // validation_context_type,
                custom_tls_certificate_selector
            )?;
            let parameters = tls_params.map(TlsParameters::try_from).transpose()?.unwrap_or_default();
            let certificates: Vec<TlsCertificate> = convert_vec!(tls_certificates)?;
            let tls_certificate_sds_secret_configs: Vec<SdsConfig> = convert_vec!(tls_certificate_sds_secret_configs)?;
            let secrets = match (tls_certificate_sds_secret_configs.len(), certificates.len()) {
                (0, 0) => Secrets::Certificates(Vec::new()),
                (_, 0) => Secrets::from(tls_certificate_sds_secret_configs),
                (0, _) => Secrets::from(certificates),
                (_, _) => {
                    return Err(GenericError::from_msg(
                        "Only one of tls_certificates OR tls_certificate_sds_secret_configs may be set",
                    ))
                },
            };
            let validation_context = validation_context_type.map(CommonTlsValidationContext::try_from).transpose()?;
            Ok(Self { parameters, secrets, validation_context })
        }
    }
    impl TryFrom<EnvoySdsSecretConfig> for SdsConfig {
        type Error = GenericError;
        fn try_from(value: EnvoySdsSecretConfig) -> Result<Self, Self::Error> {
            let EnvoySdsSecretConfig { name, sds_config } = value;
            let name: CompactString = required!(name)?.into();
            unsupported_field!(sds_config).with_name(name.clone())?;
            Ok(Self { name })
        }
    }

    impl TryFrom<EnvoyValidationContextType> for CommonTlsValidationContext {
        type Error = GenericError;
        fn try_from(value: EnvoyValidationContextType) -> Result<Self, Self::Error> {
            match value {
                EnvoyValidationContextType::ValidationContext(cert_validation_ctx) => {
                    cert_validation_ctx.try_into().map(Self::ValidationContext)
                },
                EnvoyValidationContextType::ValidationContextSdsSecretConfig(x) => {
                    SdsConfig::try_from(x).map(|sds| Self::SdsConfig(sds.name))
                },
                EnvoyValidationContextType::CombinedValidationContext(_) => {
                    Err(GenericError::unsupported_variant("CombinedValidationContext"))
                },
                EnvoyValidationContextType::ValidationContextCertificateProvider(_) => {
                    Err(GenericError::unsupported_variant("ValidationContextCertificateProvider"))
                },
                EnvoyValidationContextType::ValidationContextCertificateProviderInstance(_) => {
                    Err(GenericError::unsupported_variant("ValidationContextCertificateProviderInstance"))
                },
            }
        }
    }

    pub(crate) enum SupportedEnvoyTransportSocket {
        DownstreamTlsContext(EnvoyDownstreamTlsContext),
        UpstreamTlsContext(EnvoyUpstreamTlsContext),
    }

    impl TryFrom<Any> for SupportedEnvoyTransportSocket {
        type Error = GenericError;
        fn try_from(typed_config: Any) -> Result<Self, Self::Error> {
            match typed_config.type_url.as_str() {
                "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext" => {
                    EnvoyDownstreamTlsContext::decode(typed_config.value.as_slice())
                        .map(SupportedEnvoyTransportSocket::DownstreamTlsContext)
                        .map_err(|e| {
                            GenericError::from_msg_with_cause(
                                format!("failed to parse protobuf for \"{}\"", typed_config.type_url),
                                e,
                            )
                        })
                },
                "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext" => {
                    EnvoyUpstreamTlsContext::decode(typed_config.value.as_slice())
                        .map(SupportedEnvoyTransportSocket::UpstreamTlsContext)
                        .map_err(|e| {
                            GenericError::from_msg_with_cause(
                                format!("failed to parse protobuf for \"{}\"", typed_config.type_url),
                                e,
                            )
                        })
                },
                s => Err(GenericError::unsupported_variant(s.to_owned())),
            }
        }
    }
}
