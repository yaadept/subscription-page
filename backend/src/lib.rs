pub mod app;
pub mod config;
pub mod constants;
pub mod crypto;
pub mod marzban;
pub mod panel;
pub mod server;
pub mod session;
pub mod trust_proxy;
pub mod webpage;

use std::sync::Arc;

use app::AppState;
use config::Config;
use marzban::MarzbanResolver;
use panel::PanelClient;
use webpage::Webpage;

/// Connects to the panel and loads everything the service needs before it starts listening.
/// Errors are fatal and meant to be printed before exiting.
pub async fn init_state(config: Config) -> Result<Arc<AppState>, String> {
    let panel = PanelClient::new(&config)?;

    tracing::info!("Remnawave API URL: {}", panel.base_url());
    match panel.get_metadata_version().await {
        Ok(version) => tracing::info!("[OK] Connected to Remnawave v{version}"),
        Err(e) => {
            return Err(format!(
                "Connection to Remnawave Panel failed!\nIs the panel online and reachable from this server?\n{e}"
            ))
        }
    }

    let webpage = Webpage::bootstrap(
        &panel,
        &config.frontend_dir,
        config.subpage_config_uuid.clone(),
        config.internal_jwt_secret.clone(),
    )
    .await?;

    let marzban = config.marzban_enabled.then(|| {
        MarzbanResolver::new(
            panel.clone(),
            config.marzban_secret_keys.clone(),
            config.marzban_valid_from.as_deref(),
            config.marzban_drop_revoked,
        )
    });

    Ok(Arc::new(AppState {
        config,
        panel,
        webpage,
        marzban,
    }))
}
