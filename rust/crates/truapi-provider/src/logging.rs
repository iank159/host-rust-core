//! Artifact-owned logger; formatting and subscriber lifecycle are shared.

use tracing::Level;
use truapi_logging::Logger;

static LOGGER: Logger = Logger::new("truapi-provider", emit);

/// Initialize and apply a host-supplied verbosity setting.
pub fn set_level_from_str(level: &str) {
    LOGGER.set_level_from_str(level);
}

/// Routes a formatted line to the `console` method matching its level.
fn emit(level: Level, line: &str) {
    let js = wasm_bindgen::JsValue::from_str(line);
    match level {
        Level::ERROR => web_sys::console::error_1(&js),
        Level::WARN => web_sys::console::warn_1(&js),
        Level::INFO => web_sys::console::info_1(&js),
        Level::DEBUG | Level::TRACE => web_sys::console::debug_1(&js),
    }
}
