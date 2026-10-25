// No console window on Windows; the CLI lives in its own binary.
#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    zengav::gui::run();
}
