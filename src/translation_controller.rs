use std::fs;
use crate::AppWindow;
use slint::ComponentHandle;

const LANG_DIR: &str = "lang/";
const DIRECTION_KEY: &str = "direction";

struct LangFile {
    direction: &'static str, // always "ltr" or "rtl"
    values: Vec<String>,
}

pub fn main_controller(ui: &AppWindow, lang: &str) {
    match load_lang_file(lang) {
        Ok(lang_file) => {
            ui.global::<crate::Translations>().set_direction(lang_file.direction.into());
            apply_translations(ui, lang_file.values);
            // println!("translated the buttons");
        }
        Err(e) => eprintln!("failed to load language: {}", e),
    }
}

fn load_lang_file(lang_code: &str) -> Result<LangFile, String> {
    let path = format!("{}{}.json", LANG_DIR, lang_code);
    let contents = fs::read_to_string(&path).map_err(|e| format!("failed to read {}: {}", path, e))?;
    let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&contents).map_err(|e| format!("failed to parse {}: {}", path, e))?;
    // "LTR", "ltr", " rtl " etc. all normalize to exactly "ltr" or "rtl"
    let direction = match map.get(DIRECTION_KEY).and_then(|v| v.as_str()) {Some(d) if d.trim().eq_ignore_ascii_case("rtl") => "rtl",_ => "ltr",};
    // everything except "direction", in file order
    let values: Vec<String> = map.iter().filter(|(key, _)| key.as_str() != DIRECTION_KEY).map(|(_, v)| v.as_str().unwrap_or("").to_string()).collect();
    Ok(LangFile { direction, values })
}

fn apply_translations(ui: &AppWindow, values: Vec<String>) {
    let shared_values: Vec<slint::SharedString> = values.into_iter().map(|s| s.into()).collect();
    let model = slint::ModelRc::new(slint::VecModel::from(shared_values));
    ui.global::<crate::Translations>().set_t(model);
}
