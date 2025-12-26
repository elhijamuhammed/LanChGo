// // The whole file transfer code
// use rfd::FileDialog;

// #[derive(Serialize, Deserialize, Debug, Clone)]
// struct FileOfferMeta {
//     bundle_id: i32,
//     bundle_name: String,
//     total_size: u64,
//     file_count: usize,
// }

// #[derive(Serialize, Deserialize, Debug, Clone)]
// struct FileRequest {
//     bundle_id: i32,
// }

// #[derive(Debug, Clone)]
// struct PendingOffer {
//     from: SocketAddr,
//     meta: FileOfferMeta,
// }

// // All the handle file transfer should be moved to file_trasnfer_protocol file
// fn handle_send_file_clicked(app: AppWindow, state: &BroadcastState, sock: &UdpSocket, outgoing_bundles: &Arc<Mutex<HashMap<i32, Vec<PathBuf>>>>,) {
//     // Let user select multiple files
//     let files = FileDialog::new()
//         .set_title("Select files to send")
//         .pick_files();

//     let Some(paths) = files else {
//         return; // user canceled
//     };

//     if paths.is_empty() {
//         return;
//     }

//     // Sum total size
//     let total_size = calculate_total_size(&paths);

//     // Read current bundle number from Slint
//     let mut bundle_number = app.get_bundle_number();

//     // Decide bundle name (single file → filename, multiple → "Bundle N")
//     let bundle_name = choose_bundle_name(&paths, &mut bundle_number);

//     // Store updated bundle number back to Slint
//     app.set_bundle_number(bundle_number);

//     // Store full paths in outgoing map (we will send only the first for now)
//     {
//         let mut map = outgoing_bundles.lock().unwrap();
//         map.insert(bundle_number, paths.clone());
//     }

//     // Build metadata we send in FOFR
//     let meta = FileOfferMeta {
//         bundle_id: bundle_number,
//         bundle_name: bundle_name.clone(),
//         total_size,
//         file_count: paths.len(),
//     };

//     // Human readable size → local echo
//     let size_str = readable_size(total_size);
//     let summary_line = format!("📦 {} — {}", bundle_name, size_str);

//     // Serialize meta as JSON
//     let meta_bytes = match serde_json::to_vec(&meta) {
//         Ok(v) => v,
//         Err(_) => return,
//     };

//     const FILE_OFFER_MAGIC: &[u8] = b"FOFR";
//     let mut packet = Vec::from(FILE_OFFER_MAGIC);
//     packet.extend_from_slice(&meta_bytes);

//     if let Err(_e) = broadcast_the_msg(sock, state, &packet) {
//         app.invoke_show_popupmsg();
//         return;
//     }

//     // Show our own summary in chat
//     app.invoke_append_message(summary_line.into());
// }

// /// Sum file sizes in bytes
// fn calculate_total_size(paths: &[PathBuf]) -> u64 {
//     let mut total: u64 = 0;
//     for path in paths {
//         if let Ok(metadata) = std::fs::metadata(path) {
//             total += metadata.len();
//         }
//     }
//     total
// }

// /// Decide bundle name based on how many files were picked.
// /// - If 1 file  → use the file name
// /// - If >1 file → use "Bundle N" and increment N
// fn choose_bundle_name(paths: &[PathBuf], bundle_number: &mut i32) -> String {
//     if paths.len() == 1 {
//         paths[0]
//             .file_name()
//             .unwrap_or_default()
//             .to_string_lossy()
//             .to_string()
//     } else {
//         let name = format!("Bundle {}", bundle_number);
//         *bundle_number += 1;
//         name
//     }
// }

// /// Turn bytes into "123 B", "0.95 MB", "1.23 GB", etc.
// fn readable_size(bytes: u64) -> String {
//     const KB: f64 = 1024.0;
//     const MB: f64 = KB * 1024.0;
//     const GB: f64 = MB * 1024.0;

//     let b = bytes as f64;

//     if b >= GB {
//         format!("{:.2} GB", b / GB)
//     } else if b >= 0.1 * MB {
//         // from ~0.1 MB up, show as MB (so 0.9 MB stays MB, not KB)
//         format!("{:.2} MB", b / MB)
//     } else if b >= KB {
//         format!("{:.2} KB", b / KB)
//     } else {
//         format!("{} B", bytes)
//     }
// }
