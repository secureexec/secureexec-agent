//! First-run enrollment: exchange an install token for a long-lived agent token and mTLS cert.

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use serde::{Deserialize, Serialize};

use crate::error::{AgentError, Result};

#[derive(Debug, Clone)]
pub struct EnrollmentRequest {
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub agent_version: String,
}

#[derive(Debug, Clone)]
pub struct EnrollmentArtifacts {
    pub agent_id: String,
    pub agent_token: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    pub ca_cert_pem: String,
    pub backend_grpc_url: String,
    pub tls_server_name: String,
}

#[derive(Serialize)]
struct EnrollHttpBody {
    csr: String,
    hostname: String,
    os: String,
    arch: String,
    agent_version: String,
}

#[derive(Deserialize)]
struct EnrollHttpResponse {
    agent_id: String,
    agent_token: String,
    client_cert: String,
    ca_cert: String,
    backend_grpc_url: String,
    tls_server_name: String,
}

/// Generate a fresh keypair and PEM CSR. `common_name` is a temporary CSR subject only;
/// the server replaces the signed cert subject with `agent_id`.
pub fn generate_keypair_and_csr(common_name: &str) -> Result<(String, String)> {
    let key_pair = KeyPair::generate().map_err(|e| AgentError::Config(e.to_string()))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    let mut params = CertificateParams::new(vec![])
        .map_err(|e| AgentError::Config(e.to_string()))?;
    params.distinguished_name = dn;
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| AgentError::Config(e.to_string()))?;
    let csr_pem = csr
        .pem()
        .map_err(|e| AgentError::Config(e.to_string()))?;
    Ok((key_pair.serialize_pem(), csr_pem))
}

/// `POST /api/agent/enroll` on `backend_https_url` (scheme + host, no trailing slash required).
pub async fn enroll(
    backend_https_url: &str,
    install_token: &str,
    req: EnrollmentRequest,
    client_key_pem: &str,
    csr_pem: &str,
) -> Result<EnrollmentArtifacts> {
    let base = backend_https_url.trim_end_matches('/');
    let url = format!("{}/api/agent/enroll", base);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| AgentError::Config(format!("enroll HTTP client: {}", e)))?;

    let body = EnrollHttpBody {
        csr: csr_pem.to_string(),
        hostname: req.hostname,
        os: req.os,
        arch: req.arch,
        agent_version: req.agent_version,
    };

    let resp = client
        .post(&url)
        .header(
            "Authorization",
            format!("Bearer {}", install_token.trim()),
        )
        .json(&body)
        .send()
        .await
        .map_err(|e| AgentError::Config(format!("enroll request: {}", e)))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(AgentError::Config(format!(
            "enroll failed HTTP {}: {}",
            status, text
        )));
    }

    let parsed: EnrollHttpResponse = resp
        .json()
        .await
        .map_err(|e| AgentError::Config(format!("enroll JSON: {}", e)))?;

    Ok(EnrollmentArtifacts {
        agent_id: parsed.agent_id,
        agent_token: parsed.agent_token,
        client_cert_pem: parsed.client_cert,
        client_key_pem: client_key_pem.to_string(),
        ca_cert_pem: parsed.ca_cert,
        backend_grpc_url: parsed.backend_grpc_url,
        tls_server_name: parsed.tls_server_name,
    })
}
