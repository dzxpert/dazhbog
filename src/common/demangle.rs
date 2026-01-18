//! Universal symbol demangling support.
//!
//! Supports:
//! - C++ (Itanium ABI / GCC / Clang)
//! - C++ (MSVC)
//! - Rust
//! - Swift
//! - Go
//! - D
//! - Objective-C (basic)

/// Result of demangling attempt
#[derive(Debug, Clone)]
pub struct DemangleResult {
    /// The demangled name (or original if demangling failed)
    pub name: String,
    /// Whether demangling was successful
    pub demangled: bool,
    /// Detected language/mangling scheme
    pub lang: Option<&'static str>,
}

/// Attempt to demangle a symbol name using all known schemes.
/// Returns the demangled name if successful, otherwise the original.
pub fn demangle(name: &str) -> DemangleResult {
    let name = name.trim();

    if name.is_empty() {
        return DemangleResult {
            name: name.to_string(),
            demangled: false,
            lang: None,
        };
    }

    // Try each demangling scheme in order of likelihood

    // 1. Rust (starts with _R or _ZN...E with rust-specific patterns)
    if let Some(result) = try_demangle_rust(name) {
        return result;
    }

    // 2. Swift (starts with _$s, _$S, $s, $S, _T)
    if let Some(result) = try_demangle_swift(name) {
        return result;
    }

    // 3. MSVC C++ (starts with ? or contains @@)
    if let Some(result) = try_demangle_msvc(name) {
        return result;
    }

    // 4. Itanium C++ (starts with _Z or __Z)
    if let Some(result) = try_demangle_itanium(name) {
        return result;
    }

    // 5. Go (contains middle dot · or specific patterns)
    if let Some(result) = try_demangle_go(name) {
        return result;
    }

    // 6. D (starts with _D)
    if let Some(result) = try_demangle_d(name) {
        return result;
    }

    // 7. Try symbolic as a catch-all
    if let Some(result) = try_demangle_symbolic(name) {
        return result;
    }

    // No demangling succeeded
    DemangleResult {
        name: name.to_string(),
        demangled: false,
        lang: None,
    }
}

/// Try to demangle as Rust symbol
fn try_demangle_rust(name: &str) -> Option<DemangleResult> {
    // Rust v0 mangling starts with _R
    // Rust legacy mangling starts with _ZN and ends with E, with specific patterns
    if !name.starts_with("_R") && !name.starts_with("_ZN") && !name.starts_with("__RN") {
        return None;
    }

    match rustc_demangle::try_demangle(name) {
        Ok(demangled) => {
            // Use write! to handle potential Display errors gracefully
            let mut result = String::new();
            if std::fmt::Write::write_fmt(&mut result, format_args!("{:#}", demangled)).is_ok() {
                Some(DemangleResult {
                    name: result,
                    demangled: true,
                    lang: Some("rust"),
                })
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

/// Try to demangle as Swift symbol
fn try_demangle_swift(name: &str) -> Option<DemangleResult> {
    // Swift mangling prefixes
    if !name.starts_with("_$s")
        && !name.starts_with("_$S")
        && !name.starts_with("$s")
        && !name.starts_with("$S")
        && !name.starts_with("_T")
    {
        return None;
    }

    // Use symbolic for Swift
    match symbolic_demangle::demangle(name) {
        std::borrow::Cow::Owned(demangled) if demangled != name => Some(DemangleResult {
            name: demangled,
            demangled: true,
            lang: Some("swift"),
        }),
        _ => None,
    }
}

/// Try to demangle as MSVC C++ symbol
fn try_demangle_msvc(name: &str) -> Option<DemangleResult> {
    // MSVC mangling starts with ?
    if !name.starts_with('?') {
        return None;
    }

    match msvc_demangler::demangle(name, msvc_demangler::DemangleFlags::COMPLETE) {
        Ok(demangled) => Some(DemangleResult {
            name: demangled,
            demangled: true,
            lang: Some("c++/msvc"),
        }),
        Err(_) => None,
    }
}

/// Try to demangle as Itanium ABI C++ symbol (GCC/Clang)
fn try_demangle_itanium(name: &str) -> Option<DemangleResult> {
    // Itanium mangling starts with _Z or __Z
    if !name.starts_with("_Z") && !name.starts_with("__Z") {
        return None;
    }

    // Try cpp_demangle first (more complete)
    let to_demangle = if name.starts_with("__Z") {
        &name[1..] // Strip one underscore for macOS symbols
    } else {
        name
    };

    match cpp_demangle::Symbol::new(to_demangle) {
        Ok(sym) => {
            // Use write! to handle potential Display errors gracefully
            // (to_string() panics if Display::fmt returns an error)
            let mut demangled = String::new();
            if std::fmt::Write::write_fmt(&mut demangled, format_args!("{}", sym)).is_ok() {
                Some(DemangleResult {
                    name: demangled,
                    demangled: true,
                    lang: Some("c++"),
                })
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

/// Try to demangle as Go symbol
fn try_demangle_go(name: &str) -> Option<DemangleResult> {
    // Go symbols often contain middle dot (·) or specific patterns
    // Go 1.18+ uses a different scheme

    // Check for Go-style patterns
    let is_go = name.contains("·") || 
                name.contains("%c2%b7") || // URL-encoded middle dot
                (name.starts_with("go.") || name.starts_with("type.") || 
                 name.starts_with("main.") || name.starts_with("runtime."));

    if !is_go {
        return None;
    }

    // Basic Go demangling: replace middle dot with .
    let demangled = name
        .replace("·", ".")
        .replace("%c2%b7", ".")
        .replace("%2e", ".");

    // Remove common Go prefixes for cleaner display
    let demangled = demangled
        .trim_start_matches("go.")
        .trim_start_matches("type.")
        .to_string();

    if demangled != name {
        Some(DemangleResult {
            name: demangled,
            demangled: true,
            lang: Some("go"),
        })
    } else {
        None
    }
}

/// Try to demangle as D symbol
fn try_demangle_d(name: &str) -> Option<DemangleResult> {
    // D mangling starts with _D
    if !name.starts_with("_D") {
        return None;
    }

    // Basic D demangling (D uses a leb128-style length-prefixed encoding)
    // For full support, would need a dedicated D demangler
    // For now, try symbolic
    match symbolic_demangle::demangle(name) {
        std::borrow::Cow::Owned(demangled) if demangled != name => Some(DemangleResult {
            name: demangled,
            demangled: true,
            lang: Some("d"),
        }),
        _ => None,
    }
}

/// Try symbolic-demangle as a catch-all
fn try_demangle_symbolic(name: &str) -> Option<DemangleResult> {
    match symbolic_demangle::demangle(name) {
        std::borrow::Cow::Owned(demangled) if demangled != name => {
            // Detect language from the demangled result or original pattern
            let lang = if name.starts_with("_Z") || name.starts_with("__Z") {
                Some("c++")
            } else if name.starts_with('?') {
                Some("c++/msvc")
            } else if name.starts_with("_$") || name.starts_with("$s") {
                Some("swift")
            } else if name.starts_with("_R") {
                Some("rust")
            } else {
                Some("unknown")
            };

            Some(DemangleResult {
                name: demangled,
                demangled: true,
                lang,
            })
        }
        _ => None,
    }
}

/// Demangle a name, returning just the demangled string (or original if failed)
pub fn demangle_simple(name: &str) -> String {
    demangle(name).name
}

/// Check if a name appears to be mangled
pub fn is_mangled(name: &str) -> bool {
    let name = name.trim();

    // Common mangling prefixes
    name.starts_with("_Z") ||      // Itanium C++
    name.starts_with("__Z") ||     // macOS Itanium C++
    name.starts_with('?') ||       // MSVC C++
    name.starts_with("_R") ||      // Rust v0
    name.starts_with("_$s") ||     // Swift
    name.starts_with("_$S") ||     // Swift
    name.starts_with("$s") ||      // Swift (no underscore)
    name.starts_with("$S") ||      // Swift (no underscore)
    name.starts_with("_D") ||      // D
    name.contains("@@") ||         // MSVC decorated
    name.contains("·") // Go
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_itanium_cpp() {
        let result = demangle("_ZN3foo3barEv");
        assert!(result.demangled);
        assert_eq!(result.lang, Some("c++"));
        assert!(result.name.contains("foo"));
        assert!(result.name.contains("bar"));
    }

    #[test]
    fn test_msvc_cpp() {
        let result = demangle("?foo@@YAHXZ");
        assert!(result.demangled);
        assert_eq!(result.lang, Some("c++/msvc"));
    }

    #[test]
    fn test_rust() {
        let result = demangle("_ZN4core3ptr13drop_in_place17h1234567890abcdefE");
        assert!(result.demangled);
        // Could be detected as rust or c++ depending on heuristics
    }

    #[test]
    fn test_not_mangled() {
        let result = demangle("main");
        assert!(!result.demangled);
        assert_eq!(result.name, "main");
    }

    #[test]
    fn test_go_middle_dot() {
        let result = demangle("main·init");
        assert!(result.demangled);
        assert_eq!(result.lang, Some("go"));
        assert_eq!(result.name, "main.init");
    }
}
