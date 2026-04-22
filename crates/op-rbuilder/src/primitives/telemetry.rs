use crate::args::TelemetryArgs;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{Layer, filter::Targets};
use url::Url;

/// Default trace filter for telemetry layers
fn default_trace_filter() -> Targets {
    Targets::new()
        .with_default(LevelFilter::WARN)
        .with_target("op_rbuilder", LevelFilter::INFO)
        .with_target("payload_builder", LevelFilter::DEBUG)
        .with_target("tx_trace", LevelFilter::DEBUG)
}

/// Setup telemetry layer with sampling and custom endpoint configuration
pub fn setup_telemetry_layer(
    args: &TelemetryArgs,
) -> eyre::Result<impl Layer<tracing_subscriber::Registry>> {
    if args.otlp_endpoint.is_none() {
        return Err(eyre::eyre!("OTLP endpoint is not set"));
    }

    // Otlp uses evn vars inside

    if let Some(headers) = &args.otlp_headers {
        unsafe { std::env::set_var("OTEL_EXPORTER_OTLP_HEADERS", headers) };
    }

    // Create OTLP layer with custom configuration
    let mut endpoint =
        Url::parse(args.otlp_endpoint.as_ref().unwrap()).expect("Invalid OTLP endpoint");
    reth_tracing_otlp::OtlpProtocol::Http.validate_endpoint(&mut endpoint)?;

    let config = reth_tracing_otlp::OtlpConfig::new(
        "op-rbuilder",
        endpoint,
        reth_tracing_otlp::OtlpProtocol::Http,
        None,
    )?;
    let otlp_layer = reth_tracing_otlp::span_layer(config)?;

    let filtered_layer = otlp_layer.with_filter(default_trace_filter());

    Ok(filtered_layer)
}

/// Setup Loki layer that pushes logs directly over HTTP.
/// Returns the tracing layer and a background task that must be spawned.
#[cfg(feature = "loki")]
pub fn setup_loki_layer(
    loki_url: &str,
) -> eyre::Result<(
    impl Layer<tracing_subscriber::Registry>,
    tracing_loki::BackgroundTask,
)> {
    let url = Url::parse(loki_url)?;

    let (layer, task) = tracing_loki::builder()
        .label("service", "op-rbuilder")
        .map_err(|e| eyre::eyre!(e))?
        .build_url(url)
        .map_err(|e| eyre::eyre!(e))?;

    let filtered_layer = layer.with_filter(default_trace_filter());

    Ok((filtered_layer, task))
}
