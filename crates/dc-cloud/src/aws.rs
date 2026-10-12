//! AWS EC2 / EBS driver — DescribeVolumes, AttachVolume, DetachVolume over
//! the EC2 query API, fully SigV4-signed.
//!
//! XML handling: EC2 returns XML. We scan the few fields we bind into the
//! audit receipt with a strict, allocation-bounded extractor rather than
//! pulling a full XML parser into the appliance (see `xml_field`).

use crate::imds::{ImdsClient, InstanceIdentity};
use crate::sigv4::{AwsCredentials, SigV4Request, sign as sigv4_sign};
use crate::transport::{CloudTransport, TransportResponse};
use dc_core::DcError;
use std::time::Duration;

pub const EC2_API_VERSION: &str = "2016-11-15";

pub struct Ec2Driver {
    pub region: String,
    pub credentials: AwsCredentials,
    pub instance: InstanceIdentity,
    transport: Box<dyn CloudTransport>,
    /// UTC timestamp source (injectable for deterministic tests).
    clock: Box<dyn Fn() -> String + Send + Sync>,
}

impl Ec2Driver {
    /// Connect on an EC2 instance: resolve identity and instance-profile
    /// credentials via IMDSv2.
    pub fn from_instance_metadata(transport: Box<dyn CloudTransport>) -> Result<Self, DcError> {
        let imds = ImdsClient::connect()?;
        let instance = imds.instance_identity()?;
        let credentials = imds.instance_profile_credentials()?;
        Ok(Ec2Driver {
            region: instance.region.clone(),
            credentials,
            instance,
            transport,
            clock: Box::new(chrono_now),
        })
    }

    /// Explicit construction (tests, offline tooling, keys from the
    /// environment).
    pub fn new(
        region: &str,
        credentials: AwsCredentials,
        instance: InstanceIdentity,
        transport: Box<dyn CloudTransport>,
    ) -> Self {
        Ec2Driver {
            region: region.to_string(),
            credentials,
            instance,
            transport,
            clock: Box::new(chrono_now),
        }
    }

    fn host(&self) -> String {
        format!("ec2.{}.amazonaws.com", self.region)
    }

    /// Issue one signed EC2 query-API call.
    fn ec2_call(
        &self,
        action: &str,
        params: &[(&str, &str)],
    ) -> Result<TransportResponse, DcError> {
        let mut query: Vec<(String, String)> = vec![
            ("Action".to_string(), action.to_string()),
            ("Version".to_string(), EC2_API_VERSION.to_string()),
        ];
        for (k, v) in params {
            query.push((k.to_string(), v.to_string()));
        }

        let host = self.host();
        let amz_date = (self.clock)();
        let sig_req = SigV4Request {
            method: "GET",
            host: &host,
            canonical_uri: "/",
            query: &query,
            amz_date: &amz_date,
            region: &self.region,
            service: "ec2",
            payload: b"",
            session_token: self.credentials.session_token.as_deref(),
        };
        let (headers, _sig) = sigv4_sign(&self.credentials, &sig_req)?;
        let url = format!(
            "https://{}/?{}",
            host,
            crate::sigv4::canonical_query_string(&query)
        );
        let resp = self.transport.request("GET", &url, &headers, b"")?;
        if !resp.is_ok() {
            return Err(DcError::Internal(format!(
                "EC2 {action} failed: HTTP {} — {}",
                resp.status,
                truncate(&resp.body_str(), 300)
            )));
        }
        Ok(resp)
    }

    /// DescribeVolumes for a single volume id.
    pub fn describe_volume_xml(&self, volume_id: &str) -> Result<String, DcError> {
        Ok(self
            .ec2_call("DescribeVolumes", &[("VolumeId.1", volume_id)])?
            .body_str())
    }
}

/// Minimal UTC timestamp (YYYYMMDDTHHMMSSZ) without a chrono dependency:
/// epoch seconds through the civil-from-days algorithm.
fn chrono_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_epoch(secs)
}

pub fn format_epoch(secs: u64) -> String {
    let days = secs / 86400;
    let rem = secs % 86400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Howard Hinnant's civil_from_days.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mth <= 2 { y + 1 } else { y };
    format!("{y:04}{mth:02}{d:02}T{h:02}{m:02}{s:02}Z")
}

/// Extract a top-level-ish element's text from EC2 XML responses.
/// Strict: returns None when the tag is absent or unbalanced.
pub fn xml_field(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    if end < start {
        return None;
    }
    Some(xml[start..end].to_string())
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}
// ---------------------------------------------------------------------------
// CloudDriver implementation
// ---------------------------------------------------------------------------

impl crate::CloudDriver for Ec2Driver {
    fn provider(&self) -> &'static str {
        "aws"
    }

    fn describe_volume(&self, volume_id: &str) -> Result<crate::CloudVolume, DcError> {
        let xml = self.describe_volume_xml(volume_id)?;
        let volume_id_parsed = xml_field(&xml, "volumeId").ok_or_else(|| {
            DcError::Internal("DescribeVolumes: no volumeId in response".to_string())
        })?;
        if volume_id_parsed != volume_id {
            return Err(DcError::Internal(format!(
                "DescribeVolumes: response describes {} but {} was requested",
                volume_id_parsed, volume_id
            )));
        }
        let size_gib: u64 = xml_field(&xml, "size")
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| DcError::Internal("DescribeVolumes: no size".to_string()))?;
        let encrypted = xml_field(&xml, "encrypted").as_deref() == Some("true");
        let state = xml_field(&xml, "status").unwrap_or_else(|| "unknown".to_string());
        let attached_device = xml_field(&xml, "device");
        Ok(crate::CloudVolume {
            volume_id: volume_id_parsed,
            size_gib,
            encrypted,
            kms_key_arn: xml_field(&xml, "kmsKeyId"),
            availability_zone: xml_field(&xml, "availabilityZone").unwrap_or_default(),
            state,
            attached_device,
            iops: xml_field(&xml, "iops").and_then(|s| s.parse().ok()),
            volume_type: xml_field(&xml, "volumeType").unwrap_or_else(|| "standard".to_string()),
        })
    }

    fn attach_volume(&self, volume_id: &str, device: &str) -> Result<(), DcError> {
        self.ec2_call(
            "AttachVolume",
            &[
                ("VolumeId", volume_id),
                ("InstanceId", &self.instance.instance_id),
                ("Device", device),
            ],
        )?;
        Ok(())
    }

    fn detach_volume(&self, volume_id: &str, device: &str) -> Result<(), DcError> {
        self.ec2_call(
            "DetachVolume",
            &[("VolumeId", volume_id), ("Device", device)],
        )?;
        Ok(())
    }

    fn wait_state(
        &self,
        volume_id: &str,
        want: &str,
        timeout: Duration,
    ) -> Result<crate::CloudVolume, DcError> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let vol = self.describe_volume(volume_id)?;
            if vol.state == want {
                return Ok(vol);
            }
            if std::time::Instant::now() >= deadline {
                return Err(DcError::Internal(format!(
                    "volume {volume_id} stuck in state '{}' (wanted '{want}')",
                    vol.state
                )));
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    fn cloud_context(&self, volume_id: &str) -> Result<crate::CloudContext, DcError> {
        let vol = self.describe_volume(volume_id)?;
        Ok(crate::CloudContext {
            provider: "aws".to_string(),
            account_id: Some(self.instance.account_id.clone()),
            project_id: None,
            volume_id: vol.volume_id.clone(),
            kms_key_arn: vol.kms_key_arn.clone(),
            region: self.region.clone(),
            availability_zone: vol.availability_zone.clone(),
            performed_by_instance: Some(self.instance.instance_id.clone()),
            attachment_device: vol.attached_device.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_formatting() {
        assert_eq!(format_epoch(0), "19700101T000000Z");
        assert_eq!(format_epoch(1_760_000_000), "20251009T085320Z");
    }

    #[test]
    fn xml_field_extraction() {
        let doc = r#"<DescribeVolumesResponse><volumeSet><item>
            <volumeId>vol-0abc123</volumeId>
            <size>512</size>
            <encrypted>true</encrypted>
            <kmsKeyId>arn:aws:kms:eu-west-1:111:key/222</kmsKeyId>
            <availabilityZone>eu-west-1a</availabilityZone>
            <status>available</status>
        </item></volumeSet></DescribeVolumesResponse>"#;
        assert_eq!(xml_field(doc, "volumeId").as_deref(), Some("vol-0abc123"));
        assert_eq!(
            xml_field(doc, "kmsKeyId").as_deref(),
            Some("arn:aws:kms:eu-west-1:111:key/222")
        );
        assert_eq!(xml_field(doc, "encrypted").as_deref(), Some("true"));
        assert_eq!(xml_field(doc, "absent"), None);
    }
}
