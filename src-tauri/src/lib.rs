pub mod commands;
pub mod db;
pub mod detection;
pub mod demo;
pub mod error;
pub mod export;
pub mod ingest;
pub mod investigation;
pub mod pcap;
pub mod query;
pub mod state;
pub mod types;
pub mod workspace;

use tauri::Manager;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let dir = app
                .path()
                .app_data_dir()
                .map_err(|e| format!("cannot resolve app data dir: {e}"))?;
            std::fs::create_dir_all(&dir)?;
            let db = db::Db::open(dir.join("nullplinth.db"))?;
            app.manage(state::AppState { db });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::list_datasets,
            commands::delete_dataset,
            commands::get_overview,
            commands::network_topology,
            commands::load_demo_data,
            commands::workspace_state,
            commands::clear_workspace,
            commands::get_preferences,
            commands::save_preferences,
            commands::get_settings,
            commands::save_settings,
            commands::preview_csv,
            commands::preview_import,
            commands::import_file,
            commands::search_events,
            commands::get_event,
            commands::export_events,
            commands::import_pcap,
            commands::list_captures,
            commands::delete_capture,
            commands::search_packets,
            commands::get_packet,
            commands::list_flows,
            commands::get_flow_packets,
            commands::run_detection,
            commands::list_alerts,
            commands::get_alert,
            commands::update_alert_status,
            commands::create_investigation,
            commands::list_investigations,
            commands::get_investigation,
            commands::update_investigation,
            commands::add_investigation_note,
            commands::attach_alert_to_investigation,
            commands::export_investigation
        ])
        .run(tauri::generate_context!())
        .expect("error while running NULLPLINTH");
}