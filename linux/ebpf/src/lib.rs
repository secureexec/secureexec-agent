// Placeholder lib so Cargo accepts this crate as a build-dependency (which expects a lib target).
// The actual eBPF program is built as the binary target. Must be no_std so the crate can be
// built for bpfel-unknown-none when aya-build compiles the package.
#![no_std]
#[allow(dead_code)]
pub fn _crate_has_lib() {}
