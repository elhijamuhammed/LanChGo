use std::net::IpAddr;
use std::path::PathBuf;

use semaphore::SemaphoreGuard;
use slint::Weak;

use crate::{main_helpers, AppWindow, file_transfer_protocol::FileOffer};

pub fn spawn_mobile_download(
    sender_ip: IpAddr,
    offer: FileOffer,
    offer_id_hex: String,
    save_path: PathBuf,
    weak_ui: Weak<AppWindow>,
    permit: SemaphoreGuard<()>,
) {
    std::thread::spawn(move || {
        let _permit = permit; // ✅ hold slot for entire download

        //println!( "[MOBILE-DL] starting: sender_ip={} tcp_port={} offer_id_hex={} size={}", sender_ip, offer.tcp_port, offer_id_hex, offer.size );

        // --- 0% immediately ---
        {
            let weak_ui0 = weak_ui.clone();
            let offer_id0 = offer_id_hex.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(app) = weak_ui0.upgrade() {
                    main_helpers::set_offer_progress_text(&app, &offer_id0, true, "0%");
                }
            });
        }

        // --- progress + download ---
        let weak_ui_progress = weak_ui.clone();
        let offer_id_progress = offer_id_hex.clone();
        let total_expected = offer.size;
        let mut last_bucket: u32 = 999;
        let mut next_log_at: u64 = 5 * 1024 * 1024; // log every ~5MB

        let res = crate::tcp_file_client::download_offer_mobile(
            sender_ip,
            offer.tcp_port,
            &offer_id_hex,
            save_path,
            move |done, total| {
                // Flutter path passes total=0 -> substitute expected total
                let total = if total == 0 { total_expected } else { total };

                // ✅ debug: print bytes progress every ~5MB
                if done >= next_log_at {
                    //println!("[MOBILE-DL] progress: done={} total={}", done, total);
                    next_log_at = done + 5 * 1024 * 1024;
                }

                let bucket = main_helpers::progress_bucket_3(done, total);
                if bucket == last_bucket {
                    return;
                }
                last_bucket = bucket;

                let text = format!("{}%", bucket);

                let weak_ui = weak_ui_progress.clone();
                let offer_id = offer_id_progress.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(app) = weak_ui.upgrade() {
                        main_helpers::set_offer_progress_text(&app, &offer_id, true, &text);
                    }
                });
            },
        );

        // --- finish UI ---
        let weak_ui_done = weak_ui.clone();
        let id = offer_id_hex.clone();
        let name = offer.name.clone();

        let _ = slint::invoke_from_event_loop(move || {
            if let Some(app) = weak_ui_done.upgrade() {
                match res {
                    Ok(_) => {
                        //println!("[MOBILE-DL] finished OK: {}", id);
                        main_helpers::set_offer_progress_text(&app, &id, false, "100%");
                        app.invoke_show_temp_message(format!("✅ Download complete: {}", name).into());
                    }
                    Err(e) => {
                        //println!("[MOBILE-DL] finished ERR: {} -> {}", id, e);
                        main_helpers::set_offer_progress_text(&app, &id, false, "ERR");
                        app.invoke_show_temp_message(format!("❌ Download failed: {}", e).into());
                    }
                }
            }
        });
    });
}
