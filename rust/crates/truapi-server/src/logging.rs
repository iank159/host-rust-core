//! Artifact-owned logger; formatting and subscriber lifecycle are shared.

use tracing::Level;
pub use truapi_logging::parse_level;
use truapi_logging::{LevelFilter, Logger};

static LOGGER: Logger = Logger::new("truapi", emit);

/// Install this artifact's subscriber, respecting an existing subscriber.
pub fn init() {
    LOGGER.init();
}

/// Change live verbosity after initialization.
pub fn set_level(level: LevelFilter) {
    LOGGER.set_level(level);
}

/// Initialize and apply a host-supplied verbosity setting.
pub fn set_level_from_str(level: &str) {
    LOGGER.set_level_from_str(level);
}

#[cfg(not(target_arch = "wasm32"))]
fn emit(_level: Level, line: &str) {
    eprintln!("{line}");
}

#[cfg(target_arch = "wasm32")]
fn emit(level: Level, line: &str) {
    let js = wasm_bindgen::JsValue::from_str(line);
    match level {
        Level::ERROR => web_sys::console::error_1(&js),
        Level::WARN => web_sys::console::warn_1(&js),
        Level::INFO => web_sys::console::info_1(&js),
        Level::DEBUG | Level::TRACE => web_sys::console::debug_1(&js),
    }
}
