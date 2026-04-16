mod sensors;

use std::path::Path;

use secureexec_generic::config::AgentConfig;
use secureexec_generic::pipeline::Pipeline;
use secureexec_generic::transport::{GrpcTransport, TlsConfig};
use tracing::info;

use sensors::process::WindowsProcessSensor;
use sensors::file::WindowsFileSensor;
use sensors::network::WindowsNetworkSensor;
use sensors::registry::WindowsRegistrySensor;

const CONFIG_PATH: &str = "secureexec-agent.json";
const VERSION: &str = include_str!("../version");

#[tokio::main]
async fn main() -> secureexec_generic::error::Result<()> {
    secureexec_generic::telemetry::init();

    let config = AgentConfig::load_or_create(Path::new(CONFIG_PATH))?;
    info!(agent_id = %config.agent_id, backend = %config.backend_url, version = VERSION.trim(), "secureexec agent starting (Windows)");

    let tls = TlsConfig {
        ca_cert: config.tls_ca_cert.clone(),
        client_cert: config.tls_client_cert.clone(),
        client_key: config.tls_client_key.clone(),
        server_name: config.tls_server_name.clone(),
    };
    let transport = GrpcTransport::new(&config.backend_url, tls, config.auth_token.clone());
    let mut pipeline = Pipeline::new(config, CONFIG_PATH, VERSION.trim(), transport);

    pipeline.add_sensor(WindowsProcessSensor::new());
    pipeline.add_sensor(WindowsFileSensor::new());
    pipeline.add_sensor(WindowsNetworkSensor::new());
    pipeline.add_sensor(WindowsRegistrySensor::new());

    pipeline.run().await
}
