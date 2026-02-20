use crossterm::style::Stylize;

/// Pretty printing utilities for debugger output
pub struct Formatter;

impl Formatter {
    /// Format a value for display
    pub fn format_value(value: &str) -> String {
        // TODO: Add better formatting for different types
        value.to_string()
    }

    /// Format storage key-value pair
    pub fn format_storage_entry(key: &str, value: &str) -> String {
        format!("{} = {}", key, value)
    }

    /// Format a function call
    pub fn format_function_call(name: &str, args: Option<&str>) -> String {
        if let Some(args) = args {
            format!("{}({})", name, args)
        } else {
            format!("{}()", name)
        }
    }

    /// Format budget information
    pub fn format_budget(cpu: u64, cpu_limit: u64, mem: u64, mem_limit: u64) -> String {
        format!(
            "CPU: {}/{} ({:.1}%) | Memory: {}/{} bytes ({:.1}%)",
            cpu,
            cpu_limit,
            (cpu as f64 / cpu_limit as f64) * 100.0,
            mem,
            mem_limit,
            (mem as f64 / mem_limit as f64) * 100.0
        )
    }

    /// Format an informational message in blue.
    pub fn info(message: impl AsRef<str>) -> String {
        Self::apply_color(message.as_ref(), ColorKind::Info)
    }

    /// Format a success message in green.
    pub fn success(message: impl AsRef<str>) -> String {
        Self::apply_color(message.as_ref(), ColorKind::Success)
    }

    /// Format a warning message in yellow.
    pub fn warning(message: impl AsRef<str>) -> String {
        Self::apply_color(message.as_ref(), ColorKind::Warning)
    }

    /// Format an error message in red.
    pub fn error(message: impl AsRef<str>) -> String {
        Self::apply_color(message.as_ref(), ColorKind::Error)
    }

    /// Configure whether ANSI colors are enabled.
    pub fn configure_colors(enable: bool) {
        COLOR_ENABLED.store(enable, std::sync::atomic::Ordering::Relaxed);
    }

    /// Auto-configure color output based on environment.
    /// If NO_COLOR is set, colors are disabled.
    pub fn configure_colors_from_env() {
        let no_color = std::env::var_os("NO_COLOR").is_some();
        Self::configure_colors(!no_color);
    }

    fn apply_color(message: &str, kind: ColorKind) -> String {
        if !COLOR_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
            return message.to_string();
        }

        match kind {
            ColorKind::Info => format!("{}", message.blue()),
            ColorKind::Success => format!("{}", message.green()),
            ColorKind::Warning => format!("{}", message.yellow()),
            ColorKind::Error => format!("{}", message.red()),
        }
    }
}

#[derive(Copy, Clone)]
enum ColorKind {
    Info,
    Success,
    Warning,
    Error,
}

static COLOR_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
