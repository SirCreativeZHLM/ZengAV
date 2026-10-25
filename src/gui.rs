//! Small native window plus a tray icon. The window is the same engine as the CLI, nothing more.
use crate::db::{self, Db};
use crate::scan::{self, Detection, Options, Progress};
use crate::update;
use eframe::egui::{self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, RichText, Sense, Stroke, Vec2};
use std::path::PathBuf;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const INK: Color32 = Color32::from_rgb(0x00, 0x00, 0x00);
const PANEL: Color32 = Color32::from_rgb(0x0f, 0x0f, 0x0f);
const PANEL_HI: Color32 = Color32::from_rgb(0x1c, 0x1c, 0x1c);
const LINE: Color32 = Color32::from_rgb(0x34, 0x34, 0x34);
const FG: Color32 = Color32::from_rgb(0xff, 0xff, 0xff);
const MUTED: Color32 = Color32::from_rgb(0xa6, 0xa6, 0xa6);
const ACCENT: Color32 = Color32::from_rgb(0xff, 0xff, 0xff);
const THREAT: Color32 = Color32::from_rgb(0xff, 0xff, 0xff);
const OK: Color32 = Color32::from_rgb(0xff, 0xff, 0xff);

enum Cmd {
    Show,
    Scan,
    CheckFiles,
    Quit,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    TrayReady,
}

// ---- icon: a rounded yellow tile with a Z, drawn by distance to the three strokes ----

fn seg_dist(p: (f32, f32), a: (f32, f32), b: (f32, f32)) -> f32 {
    let (abx, aby) = (b.0 - a.0, b.1 - a.1);
    let t = (((p.0 - a.0) * abx + (p.1 - a.1) * aby) / (abx * abx + aby * aby)).clamp(0.0, 1.0);
    ((p.0 - a.0 - t * abx).powi(2) + (p.1 - a.1 - t * aby).powi(2)).sqrt()
}

/// `template` draws only a black Z on transparent, which macOS recolours for the menu bar.
fn icon_rgba(size: u32, template: bool) -> Vec<u8> {
    let s = size as f32;
    let (tl, tr, bl, br) = ((0.28 * s, 0.30 * s), (0.72 * s, 0.30 * s), (0.28 * s, 0.70 * s), (0.72 * s, 0.70 * s));
    let w = if template { 0.085 * s } else { 0.075 * s };
    let mut out = vec![0u8; (size * size * 4) as usize];
    for y in 0..size {
        for x in 0..size {
            let p = (x as f32 + 0.5, y as f32 + 0.5);
            let d = seg_dist(p, tl, tr).min(seg_dist(p, tr, bl)).min(seg_dist(p, bl, br));
            let z = (w - d + 0.5).clamp(0.0, 1.0);
            // rounded square coverage
            let (cx, cy, r) = (s / 2.0, s / 2.0, 0.22 * s);
            let (qx, qy) = ((p.0 - cx).abs() - (s / 2.0 - r), (p.1 - cy).abs() - (s / 2.0 - r));
            let sd = (qx.max(0.0).powi(2) + qy.max(0.0).powi(2)).sqrt() + qx.max(qy).min(0.0) - r;
            let tile = (0.5 - sd).clamp(0.0, 1.0);
            let i = ((y * size + x) * 4) as usize;
            if template {
                out[i + 3] = (z * 255.0) as u8;
            } else {
                // black Z over a white tile
                let a = tile;
                let (r_, g_, b_) = (255.0 * (1.0 - z), 255.0 * (1.0 - z), 255.0 * (1.0 - z));
                out[i] = r_ as u8;
                out[i + 1] = g_ as u8;
                out[i + 2] = b_ as u8;
                out[i + 3] = (a * 255.0) as u8;
            }
        }
    }
    out
}

// ---- settings ----

#[derive(Clone)]
struct Settings {
    heuristics: bool,
    close_to_tray: bool,
}

impl Settings {
    fn load() -> Self {
        let text = std::fs::read_to_string(db::data_dir().join("gui.txt")).unwrap_or_default();
        let get = |k: &str, d: bool| text.lines().find_map(|l| l.strip_prefix(&format!("{k}=")).map(|v| v.trim() == "true")).unwrap_or(d);
        Settings { heuristics: get("heuristics", false), close_to_tray: get("close_to_tray", true) }
    }

    fn save(&self) {
        let _ = std::fs::create_dir_all(db::data_dir());
        let _ = std::fs::write(
            db::data_dir().join("gui.txt"),
            format!("heuristics={}\nclose_to_tray={}\n", self.heuristics, self.close_to_tray),
        );
    }
}

// ---- scan job and results ----

struct Job {
    label: String,
    progress: Arc<Progress>,
    result: Arc<Mutex<Option<scan::Report>>>,
    started: Instant,
}

enum Verdict {
    Pending,
    Deleted,
    Accepted,
    Skipped,
    Failed(String),
}

struct Item {
    det: Detection,
    verdict: Verdict,
}

struct Findings {
    label: String,
    scanned: u64,
    unchanged: u64,
    errors: u64,
    elapsed: Duration,
    cancelled: bool,
    items: Vec<Item>,
}

enum View {
    Home,
    Scanning(Job),
    Results(Findings),
}

struct SigStatus {
    rules: String,
    hashes: String,
}

fn signature_status() -> SigStatus {
    let dir = db::data_dir();
    let rules = match std::fs::metadata(dir.join("rules.bin")) {
        Ok(m) => {
            let age = m.modified().ok().and_then(|t| t.elapsed().ok()).map(|d| d.as_secs() / 86400);
            match age {
                Some(0) => "YARA rules: downloaded today".to_string(),
                Some(d) => format!("YARA rules: downloaded {d} day{} ago", if d == 1 { "" } else { "s" }),
                None => "YARA rules: downloaded".to_string(),
            }
        }
        Err(_) => "YARA rules: not downloaded yet".to_string(),
    };
    let n = std::fs::metadata(dir.join("hashes.bin")).map(|m| m.len() / 32).unwrap_or(0);
    let hashes = if n > 0 {
        format!("Malware hashes: {} known", group(n))
    } else if update::abusech_key().is_some() {
        "Malware hashes: none yet, press Update".to_string()
    } else {
        "Malware hashes: needs a free abuse.ch key (below)".to_string()
    };
    SigStatus { rules, hashes }
}

fn group(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

struct App {
    rx: Receiver<Cmd>,
    ctx: egui::Context,
    view: View,
    settings: Settings,
    sig: SigStatus,
    key_input: String,
    update_job: Option<Arc<Mutex<Option<Vec<String>>>>>,
    update_log: Vec<String>,
    tray_ok: bool,
    quitting: bool,
}

impl App {
    fn start(&mut self, roots: Vec<PathBuf>, label: String) {
        if matches!(self.view, View::Scanning(_)) {
            return;
        }
        let progress = Arc::new(Progress::default());
        let result = Arc::new(Mutex::new(None));
        let (p2, r2, ctx) = (progress.clone(), result.clone(), self.ctx.clone());
        let heuristics = self.settings.heuristics;
        std::thread::spawn(move || {
            let db = Db::load();
            let opts = Options { heuristics, progress: Some(p2), ..Options::default() };
            let report = scan::run(&roots, &db, &opts);
            *r2.lock().unwrap() = Some(report);
            ctx.request_repaint();
        });
        self.view = View::Scanning(Job { label, progress, result, started: Instant::now() });
    }

    fn show_window(&self) {
        self.ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        self.ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        self.ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    fn pick_files(&mut self) {
        if let Some(files) = rfd::FileDialog::new().set_title("Check files").pick_files() {
            let label = if files.len() == 1 { files[0].display().to_string() } else { format!("{} files", files.len()) };
            self.start(files, label);
        }
    }

    fn pick_folder(&mut self) {
        if let Some(dir) = rfd::FileDialog::new().set_title("Check a folder").pick_folder() {
            let label = dir.display().to_string();
            self.start(vec![dir], label);
        }
    }

    fn poll(&mut self) {
        while let Ok(cmd) = self.rx.try_recv() {
            match cmd {
                Cmd::TrayReady => self.tray_ok = true,
                Cmd::Show => self.show_window(),
                Cmd::Scan => {
                    self.show_window();
                    self.start(scan::roots_for_full_scan(), "Whole computer".into());
                }
                Cmd::CheckFiles => {
                    self.show_window();
                    self.pick_files();
                }
                Cmd::Quit => {
                    self.quitting = true;
                    self.ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
        if let View::Scanning(job) = &self.view {
            let done = job.result.lock().unwrap().take();
            if let Some(report) = done {
                let cancelled = job.progress.cancel.load(Relaxed);
                let f = Findings {
                    label: job.label.clone(),
                    scanned: report.scanned,
                    unchanged: report.skipped_unchanged,
                    errors: report.errors,
                    elapsed: job.started.elapsed(),
                    cancelled,
                    items: report.detections.into_iter().map(|det| Item { det, verdict: Verdict::Pending }).collect(),
                };
                self.sig = signature_status();
                self.view = View::Results(f);
            }
        }
        if let Some(job) = &self.update_job {
            let finished = job.lock().unwrap().take();
            if let Some(log) = finished {
                self.update_log = log;
                self.update_job = None;
                self.sig = signature_status();
            }
        }
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        if ctx.input(|i| i.viewport().close_requested()) && self.settings.close_to_tray && self.tray_ok && !self.quitting {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }
        if matches!(self.view, View::Scanning(_)) || self.update_job.is_some() {
            ctx.request_repaint_after(Duration::from_millis(120));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let dropped: Vec<PathBuf> = ui.ctx().input(|i| i.raw.dropped_files.iter().map(|f| f.path().to_path_buf()).collect());
        if !dropped.is_empty() {
            let label = if dropped.len() == 1 { dropped[0].display().to_string() } else { format!("{} items", dropped.len()) };
            self.start(dropped, label);
        }
        egui::Frame::new().fill(INK).inner_margin(egui::Margin::symmetric(28, 22)).show(ui, |ui| {
            ui.set_min_size(ui.available_size());
            self.header(ui);
            ui.add_space(18.0);
            match &self.view {
                View::Home => self.home(ui),
                View::Scanning(_) => self.scanning(ui),
                View::Results(_) => self.results(ui),
            }
        });
    }
}

fn card_button(ui: &mut egui::Ui, size: Vec2, title: &str, sub: &str, primary: bool) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let hot = resp.hovered() || resp.has_focus();
    let (fill, ink, sub_ink, stroke) = if primary {
        (if hot { Color32::from_rgb(0xdc, 0xdc, 0xdc) } else { ACCENT }, INK, Color32::from_rgb(0x55, 0x55, 0x55), Stroke::NONE)
    } else {
        (if hot { PANEL_HI } else { PANEL }, FG, MUTED, Stroke::new(1.0, LINE))
    };
    let rect = if resp.is_pointer_button_down_on() { rect.shrink(1.5) } else { rect };
    ui.painter().rect(rect, CornerRadius::same(16), fill, stroke, egui::StrokeKind::Inside);
    let pad = 18.0;
    ui.painter().text(rect.left_top() + Vec2::new(pad, pad), egui::Align2::LEFT_TOP, title, egui::FontId::proportional(22.0), ink);
    ui.painter().text(rect.left_bottom() + Vec2::new(pad, -pad), egui::Align2::LEFT_BOTTOM, sub, egui::FontId::proportional(14.0), sub_ink);
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn pill(ui: &mut egui::Ui, text: &str, fill: Color32, ink: Color32, stroke: Option<Color32>) -> egui::Response {
    let mut b = egui::Button::new(RichText::new(text).color(ink).size(15.0))
        .fill(fill)
        .corner_radius(CornerRadius::same(12))
        .min_size(Vec2::new(0.0, 34.0));
    if let Some(s) = stroke {
        b = b.stroke(Stroke::new(1.0, s));
    } else {
        b = b.stroke(Stroke::NONE);
    }
    ui.add(b).on_hover_cursor(egui::CursorIcon::PointingHand)
}

impl App {
    fn header(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::new(64.0, 30.0), Sense::hover());
            ui.painter().rect_filled(rect, CornerRadius::same(6), ACCENT);
            ui.painter().text(rect.center(), egui::Align2::CENTER_CENTER, "Zeng", egui::FontId::proportional(20.0), INK);
            ui.label(RichText::new("AV").size(24.0).color(FG));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(RichText::new(concat!("v", env!("CARGO_PKG_VERSION"))).size(13.0).color(MUTED));
            });
        });
    }

    fn home(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("Scan the computer, or check what you choose.").size(30.0).color(FG));
        ui.add_space(6.0);
        ui.label(RichText::new("Nothing runs in the background while you work.").size(16.0).color(MUTED));
        ui.add_space(22.0);

        let gap = 14.0;
        let w = (ui.available_width() - gap) / 2.0;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = gap;
            if card_button(ui, Vec2::new(w, 120.0), "Scan computer", "Every drive. Can take a while.", true).clicked() {
                self.start(scan::roots_for_full_scan(), "Whole computer".into());
            }
            // The Check card holds two choices, so it is a panel with two buttons rather than one big target.
            let (rect, _) = ui.allocate_exact_size(Vec2::new(w, 120.0), Sense::hover());
            ui.painter().rect(rect, CornerRadius::same(16), PANEL, Stroke::new(1.0, LINE), egui::StrokeKind::Inside);
            ui.painter().text(rect.left_top() + Vec2::new(18.0, 18.0), egui::Align2::LEFT_TOP, "Check", egui::FontId::proportional(22.0), FG);
            let mut inner = ui.new_child(egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(rect.left_bottom() + Vec2::new(18.0, -52.0), Vec2::new(w - 36.0, 34.0))));
            inner.horizontal(|ui| {
                if pill(ui, "Files…", PANEL_HI, FG, Some(LINE)).clicked() {
                    self.pick_files();
                }
                if pill(ui, "Folder…", PANEL_HI, FG, Some(LINE)).clicked() {
                    self.pick_folder();
                }
            });
        });
        ui.add_space(10.0);
        ui.label(RichText::new("You can also drop files or folders onto this window.").size(14.0).color(MUTED));
        ui.add_space(26.0);
        self.signatures(ui);
        ui.add_space(14.0);
        self.options(ui);
        ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
            ui.label(RichText::new("Nothing is sent anywhere except the updates you ask for.").size(13.0).color(MUTED));
        });
    }

    fn signatures(&mut self, ui: &mut egui::Ui) {
        egui::Frame::new().fill(PANEL).stroke(Stroke::new(1.0, LINE)).corner_radius(CornerRadius::same(14)).inner_margin(egui::Margin::same(16)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("Signatures").size(17.0).color(FG));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let busy = self.update_job.is_some();
                    let text = if busy { "Updating…" } else { "Update now" };
                    ui.add_enabled_ui(!busy, |ui| {
                        if pill(ui, text, PANEL_HI, FG, Some(LINE)).clicked() {
                            let slot = Arc::new(Mutex::new(None));
                            let (s2, ctx) = (slot.clone(), self.ctx.clone());
                            std::thread::spawn(move || {
                                let log = update::run();
                                *s2.lock().unwrap() = Some(log);
                                ctx.request_repaint();
                            });
                            self.update_job = Some(slot);
                            self.update_log.clear();
                        }
                    });
                });
            });
            ui.add_space(4.0);
            ui.label(RichText::new(&self.sig.rules).size(14.0).color(MUTED));
            ui.label(RichText::new(&self.sig.hashes).size(14.0).color(MUTED));
            for line in &self.update_log {
                ui.label(RichText::new(line).size(13.0).color(MUTED));
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.key_input).password(true).hint_text("abuse.ch Auth-Key").desired_width(ui.available_width() - 80.0));
                if pill(ui, "Save", PANEL_HI, FG, Some(LINE)).clicked() && !self.key_input.trim().is_empty() {
                    let _ = std::fs::create_dir_all(db::data_dir());
                    let _ = std::fs::write(db::data_dir().join("abusech.key"), self.key_input.trim());
                    self.key_input.clear();
                    self.sig = signature_status();
                }
            });
        });
    }

    fn options(&mut self, ui: &mut egui::Ui) {
        let before = self.settings.clone();
        ui.checkbox(&mut self.settings.heuristics, RichText::new("Also report weak signals, like packed programs in temp folders").size(14.0).color(MUTED));
        if self.tray_ok {
            ui.checkbox(&mut self.settings.close_to_tray, RichText::new("Closing the window keeps ZengAV in the tray").size(14.0).color(MUTED));
        }
        if before.heuristics != self.settings.heuristics || before.close_to_tray != self.settings.close_to_tray {
            self.settings.save();
        }
    }

    fn scanning(&mut self, ui: &mut egui::Ui) {
        let View::Scanning(job) = &self.view else { return };
        let files = job.progress.files.load(Relaxed);
        let current = job.progress.current.lock().unwrap().clone();
        let secs = job.started.elapsed().as_secs();
        ui.label(RichText::new(if job.label == "Whole computer" { "Scanning your computer" } else { "Checking" }).size(30.0).color(FG));
        ui.add_space(6.0);
        ui.add(egui::Label::new(RichText::new(&job.label).size(15.0).color(MUTED)).truncate());
        ui.add_space(26.0);
        ui.label(RichText::new(group(files)).size(56.0).color(ACCENT));
        ui.label(RichText::new("files looked at").size(15.0).color(MUTED));
        ui.add_space(18.0);
        ui.add(egui::ProgressBar::new(0.0).animate(true).desired_width(ui.available_width()).fill(ACCENT));
        ui.add_space(12.0);
        ui.add(egui::Label::new(RichText::new(current).size(13.0).color(MUTED).monospace()).truncate());
        ui.add_space(6.0);
        ui.label(RichText::new(format!("{}:{:02} elapsed", secs / 60, secs % 60)).size(14.0).color(MUTED));
        ui.add_space(24.0);
        if pill(ui, if job.progress.cancel.load(Relaxed) { "Stopping…" } else { "Cancel" }, PANEL, FG, Some(LINE)).clicked() {
            job.progress.cancel.store(true, Relaxed);
        }
    }

    fn results(&mut self, ui: &mut egui::Ui) {
        let mut done = false;
        let View::Results(f) = &mut self.view else { return };
        let threats = f.items.len();
        let headline = if f.cancelled {
            "Stopped".to_string()
        } else if threats == 0 {
            "No threats found".to_string()
        } else {
            format!("{threats} threat{} found", if threats == 1 { "" } else { "s" })
        };
        ui.label(RichText::new(headline).size(30.0).color(if threats == 0 && !f.cancelled { OK } else { FG }));
        ui.add_space(4.0);
        let secs = f.elapsed.as_secs();
        ui.add(egui::Label::new(
            RichText::new(format!(
                "{} · {} files looked at, {} unchanged skipped, {} unreadable · {}:{:02}",
                f.label, group(f.scanned), group(f.unchanged), f.errors, secs / 60, secs % 60
            ))
            .size(14.0)
            .color(MUTED),
        ));
        ui.add_space(16.0);
        egui::ScrollArea::vertical().max_height(ui.available_height() - 56.0).auto_shrink([false, false]).show(ui, |ui| {
            for item in &mut f.items {
                egui::Frame::new().fill(PANEL).stroke(Stroke::new(1.0, LINE)).corner_radius(CornerRadius::same(14)).inner_margin(egui::Margin::same(14)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.add(egui::Label::new(RichText::new(item.det.path.display().to_string()).size(14.0).color(FG).monospace()).truncate());
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        egui::Frame::new().fill(FG).corner_radius(CornerRadius::same(8)).inner_margin(egui::Margin::symmetric(8, 2)).show(ui, |ui| {
                            ui.label(RichText::new(&item.det.reason).size(13.0).color(INK));
                        });
                        ui.label(RichText::new(&item.det.hash[..12]).size(13.0).color(MUTED).monospace());
                    });
                    ui.add_space(8.0);
                    match &item.verdict {
                        Verdict::Pending => {
                            ui.horizontal(|ui| {
                                if pill(ui, "Delete", FG, INK, None).clicked() {
                                    item.verdict = match scan::delete_file(&item.det.path) {
                                        Ok(()) => Verdict::Deleted,
                                        Err(e) => Verdict::Failed(e.to_string()),
                                    };
                                }
                                if pill(ui, "Accept", PANEL_HI, FG, Some(LINE)).clicked() {
                                    item.verdict = match db::accept(&item.det.hash, &item.det.path.display().to_string()) {
                                        Ok(()) => Verdict::Accepted,
                                        Err(e) => Verdict::Failed(e.to_string()),
                                    };
                                }
                                if pill(ui, "Skip", PANEL_HI, FG, Some(LINE)).clicked() {
                                    item.verdict = Verdict::Skipped;
                                }
                            });
                        }
                        Verdict::Deleted => {
                            ui.label(RichText::new("Deleted").size(14.0).color(FG));
                        }
                        Verdict::Accepted => {
                            ui.label(RichText::new("Accepted. This exact file content won't be flagged again.").size(14.0).color(MUTED));
                        }
                        Verdict::Skipped => {
                            ui.label(RichText::new("Skipped").size(14.0).color(MUTED));
                        }
                        Verdict::Failed(e) => {
                            ui.label(RichText::new(format!("Could not finish: {e}")).size(14.0).color(THREAT));
                        }
                    }
                });
                ui.add_space(8.0);
            }
        });
        ui.add_space(10.0);
        if pill(ui, "Done", ACCENT, INK, None).clicked() {
            done = true;
        }
        if done {
            self.view = View::Home;
        }
    }
}

// ---- tray ----

fn tray_menu() -> tray_icon::menu::Menu {
    use tray_icon::menu::{Menu, MenuId, MenuItem, PredefinedMenuItem};
    let menu = Menu::new();
    let items = [
        MenuItem::with_id(MenuId::new("show"), "Open ZengAV", true, None),
        MenuItem::with_id(MenuId::new("scan"), "Scan computer", true, None),
        MenuItem::with_id(MenuId::new("check"), "Check files…", true, None),
    ];
    for i in &items {
        let _ = menu.append(i);
    }
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&MenuItem::with_id(MenuId::new("quit"), "Quit ZengAV", true, None));
    menu
}

fn make_tray() -> Result<tray_icon::TrayIcon, String> {
    let template = cfg!(target_os = "macos");
    let size = if template { 44 } else { 64 };
    let icon = tray_icon::Icon::from_rgba(icon_rgba(size, template), size, size).map_err(|e| e.to_string())?;
    let b = tray_icon::TrayIconBuilder::new().with_menu(Box::new(tray_menu())).with_tooltip("ZengAV");
    #[cfg(target_os = "macos")]
    let b = b.with_icon_templated(icon);
    #[cfg(not(target_os = "macos"))]
    let b = b.with_icon(icon);
    b.build().map_err(|e| e.to_string())
}

fn wire_events(tx: Sender<Cmd>, ctx: egui::Context) {
    use tray_icon::menu::MenuEvent;
    let (t1, c1) = (tx.clone(), ctx.clone());
    MenuEvent::set_event_handler(Some(move |e: MenuEvent| {
        let cmd = match e.id.0.as_str() {
            "show" => Cmd::Show,
            "scan" => Cmd::Scan,
            "check" => Cmd::CheckFiles,
            "quit" => Cmd::Quit,
            _ => return,
        };
        let _ = t1.send(cmd);
        c1.request_repaint();
    }));
    tray_icon::TrayIconEvent::set_event_handler(Some(move |e: tray_icon::TrayIconEvent| {
        // A plain click on Windows opens the window; the menu is on the right click.
        if let tray_icon::TrayIconEvent::DoubleClick { .. } = e {
            let _ = tx.send(Cmd::Show);
            ctx.request_repaint();
        }
    }));
}

// ---- entry ----

fn fonts() -> FontDefinitions {
    let mut f = FontDefinitions::default();
    f.font_data.insert("familjen".into(), Arc::new(FontData::from_static(include_bytes!("../assets/FamiljenGrotesk.ttf"))));
    f.families.entry(FontFamily::Proportional).or_default().insert(0, "familjen".into());
    f
}

fn style(ctx: &egui::Context) {
    for theme in [egui::Theme::Dark, egui::Theme::Light] {
        ctx.set_visuals_of(theme, {
            let mut v = egui::Visuals::dark();
            v.override_text_color = None;
            v.panel_fill = INK;
            v.window_fill = INK;
            v.extreme_bg_color = PANEL;
            v.selection.bg_fill = ACCENT;
            v.selection.stroke = Stroke::new(1.0, INK);
            v.hyperlink_color = ACCENT;
            v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, MUTED);
            v.widgets.inactive.fg_stroke = Stroke::new(1.0, FG);
            v.widgets.hovered.fg_stroke = Stroke::new(1.0, FG);
            v.widgets.active.fg_stroke = Stroke::new(1.0, FG);
            v
        });
    }
    ctx.set_theme(egui::Theme::Dark);
    ctx.global_style_mut(|s| {
        s.spacing.item_spacing = Vec2::new(10.0, 8.0);
        s.spacing.button_padding = Vec2::new(14.0, 7.0);
    });
}

pub fn run() {
    let (tx, rx) = channel::<Cmd>();
    let size = 128;
    let icon = egui::IconData { rgba: icon_rgba(size, false), width: size, height: size };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("ZengAV")
            .with_inner_size([560.0, 700.0])
            .with_min_inner_size([480.0, 560.0])
            .with_icon(Arc::new(icon))
            .with_drag_and_drop(true),
        ..Default::default()
    };
    let result = eframe::run_native(
        "ZengAV",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_fonts(fonts());
            style(&cc.egui_ctx);
            wire_events(tx.clone(), cc.egui_ctx.clone());
            let mut tray_ok = false;
            // macOS and Windows create the tray on the UI thread, inside the running event loop.
            #[cfg(not(target_os = "linux"))]
            {
                match make_tray() {
                    Ok(t) => {
                        tray_ok = true;
                        // Keep it alive for the life of the process.
                        std::mem::forget(t);
                    }
                    Err(e) => eprintln!("tray unavailable: {e}"),
                }
            }
            // GTK needs its own thread and main loop for the indicator.
            #[cfg(target_os = "linux")]
            {
                let (t2, c2) = (tx.clone(), cc.egui_ctx.clone());
                std::thread::spawn(move || {
                    if gtk::init().is_err() {
                        return;
                    }
                    match make_tray() {
                        Ok(t) => {
                            let _ = t2.send(Cmd::TrayReady);
                            c2.request_repaint();
                            std::mem::forget(t);
                            gtk::main();
                        }
                        Err(e) => eprintln!("tray unavailable: {e}"),
                    }
                });
            }
            let mut app = App {
                rx,
                ctx: cc.egui_ctx.clone(),
                view: View::Home,
                settings: Settings::load(),
                sig: signature_status(),
                key_input: String::new(),
                update_job: None,
                update_log: Vec::new(),
                tray_ok,
                quitting: false,
            };
            // `zengav-gui <path>...` opens straight into a check of those paths.
            let args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).filter(|p| p.exists()).collect();
            if !args.is_empty() {
                let label = if args.len() == 1 { args[0].display().to_string() } else { format!("{} items", args.len()) };
                app.start(args, label);
            }
            Ok(Box::new(app))
        }),
    );
    if let Err(e) = result {
        eprintln!("ZengAV could not start its window: {e}");
    }
}
