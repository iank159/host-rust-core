//! Reloadable tracing and formatting shared by host artifacts.

use core::fmt::{self, Write as _};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Record};
use tracing::{Event, Id, Level, Subscriber};
use tracing_subscriber::Registry;
pub use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt as _};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::reload;

/// One embedding artifact's subscriber state and output destination.
/// Separate WASM artifacts keep separate instances while sharing this layer.
pub struct Logger {
    prefix: &'static str,
    emit: fn(Level, &str),
    reload: OnceLock<Option<reload::Handle<LevelFilter, Registry>>>,
    trace_spans: AtomicBool,
}

impl Logger {
    /// Configure a logger without installing a subscriber.
    pub const fn new(prefix: &'static str, emit: fn(Level, &str)) -> Self {
        Self {
            prefix,
            emit,
            reload: OnceLock::new(),
            trace_spans: AtomicBool::new(false),
        }
    }

    /// Install once; leave an application's existing subscriber alone.
    pub fn init(&'static self) {
        self.reload.get_or_init(|| {
            let (filter, handle) = reload::Layer::<LevelFilter, Registry>::new(LevelFilter::OFF);
            let subscriber = Registry::default().with(ConsoleLayer(self).with_filter(filter));
            tracing::subscriber::set_global_default(subscriber)
                .ok()
                .map(|()| handle)
        });
    }

    /// Change verbosity after initialization.
    pub fn set_level(&self, level: LevelFilter) {
        self.trace_spans
            .store(level == LevelFilter::TRACE, Ordering::Relaxed);
        if let Some(Some(handle)) = self.reload.get() {
            let _ = handle.reload(level);
        }
    }

    /// Initialize and apply a host-supplied verbosity setting.
    pub fn set_level_from_str(&'static self, level: &str) {
        self.init();
        self.set_level(parse_level(level));
        tracing::info!(level, "log level set");
    }
}

/// Parse a host-supplied level string. Unknown values disable logging.
pub fn parse_level(level: &str) -> LevelFilter {
    match level.to_ascii_lowercase().as_str() {
        "error" => LevelFilter::ERROR,
        "warn" | "warning" => LevelFilter::WARN,
        "info" => LevelFilter::INFO,
        "debug" => LevelFilter::DEBUG,
        "trace" => LevelFilter::TRACE,
        _ => LevelFilter::OFF,
    }
}

/// Routes each event to the console method matching its level.
struct ConsoleLayer(&'static Logger);

impl<S> Layer<S> for ConsoleLayer
where
    S: Subscriber,
    S: for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        let mut visitor = EventVisitor::default();
        attrs.record(&mut visitor);
        span.extensions_mut().insert(SpanFields {
            fields: visitor.fields,
        });
        if self.0.trace_spans.load(Ordering::Relaxed) {
            emit_span(self.0, "new", &span);
        }
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        let mut visitor = EventVisitor::default();
        values.record(&mut visitor);
        if visitor.fields.is_empty() {
            return;
        }
        let mut extensions = span.extensions_mut();
        if let Some(fields) = extensions.get_mut::<SpanFields>() {
            if !fields.fields.is_empty() {
                fields.fields.push_str(", ");
            }
            fields.fields.push_str(&visitor.fields);
        } else {
            extensions.insert(SpanFields {
                fields: visitor.fields,
            });
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        if !self.0.trace_spans.load(Ordering::Relaxed) {
            return;
        }
        let Some(span) = ctx.span(&id) else {
            return;
        };
        emit_span(self.0, "close", &span);
    }

    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);

        let mut line = format!("[{}] {} {}", self.0.prefix, meta.level(), meta.target());
        if !visitor.message.is_empty() {
            let _ = write!(line, ": {}", visitor.message);
        }
        if !visitor.fields.is_empty() {
            let _ = write!(line, " {{{}}}", visitor.fields);
        }
        (self.0.emit)(*meta.level(), &line);
    }
}

#[derive(Default)]
struct SpanFields {
    fields: String,
}

fn emit_span<S>(logger: &Logger, kind: &str, span: &tracing_subscriber::registry::SpanRef<'_, S>)
where
    S: Subscriber,
    S: for<'a> LookupSpan<'a>,
{
    let meta = span.metadata();
    let mut line = format!("[{}] TRACE {}: span {}", logger.prefix, meta.target(), kind);
    let extensions = span.extensions();
    let fields = extensions.get::<SpanFields>();
    let _ = write!(line, " {{span={:?}", meta.name());
    if let Some(fields) = fields
        && !fields.fields.is_empty()
    {
        let _ = write!(line, ", {}", fields.fields);
    }
    line.push('}');
    (logger.emit)(Level::TRACE, &line);
}

/// Collects the implicit `message` field separately from explicit key-values.
#[derive(Default)]
struct EventVisitor {
    message: String,
    fields: String,
}

impl Visit for EventVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            if !self.fields.is_empty() {
                self.fields.push_str(", ");
            }
            let _ = write!(self.fields, "{}={value:?}", field.name());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static LOGGER: Logger = Logger::new("test-host", |_, line| {
        LINES.lock().unwrap().push(line.into())
    });

    #[test]
    fn formatting_preserves_event_fields_and_span_updates() {
        LOGGER.set_level(LevelFilter::TRACE);
        let subscriber = Registry::default().with(ConsoleLayer(&LOGGER));
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("operation", stage = "start");
            span.record("stage", "finish");
            tracing::info!(answer = 42, "ready");
        });
        let lines = LINES.lock().unwrap();
        assert!(
            lines.iter().any(|line| line.starts_with("[test-host] INFO")
                && line.ends_with(": ready {answer=42}"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("span close") && line.contains("stage=\"finish\""))
        );
    }

    #[test]
    fn initialization_preserves_a_foreign_subscriber() {
        tracing::subscriber::set_global_default(Registry::default()).unwrap();
        static FOREIGN: Logger =
            Logger::new("unused", |_, _| panic!("foreign subscriber was replaced"));
        FOREIGN.init();
        FOREIGN.init();
        FOREIGN.set_level(LevelFilter::TRACE);
        assert!(matches!(FOREIGN.reload.get(), Some(None)));
    }

    #[test]
    fn host_level_strings_are_case_insensitive_and_unknown_disables() {
        assert_eq!(parse_level("WARNING"), LevelFilter::WARN);
        assert_eq!(parse_level("trace"), LevelFilter::TRACE);
        assert_eq!(parse_level("invalid"), LevelFilter::OFF);
    }
}
