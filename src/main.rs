// this is our firmware patcher tool
// combines the api stuff and gui in one file
// also this is the start of my code 
//  i really couldnt be bothered to split it up right now
// so pack it up just this once and call it a day

use eframe::egui;

// the api part - handles scanning files and stuff
struct FileInfo {
    path: String,
    file_type: String,
    size: u64,
}

struct FirmwarePatcher {
    verbose: bool,
}

impl FirmwarePatcher {
    fn new() -> Self {
        FirmwarePatcher { verbose: false }
    }
    
    // look for firmware files in the current folder
    fn scan(&self) -> Vec<FileInfo> {
        let mut found_files = Vec::new();
        
        // file extensions we're looking for
        let firmware_extensions = vec![".tar.md5", ".md5", ".tar", ".zip", ".img"];
        
        // try to read current directory
        if let Ok(folder_contents) = std::fs::read_dir("./") {
            for maybe_entry in folder_contents {
                if let Ok(entry) = maybe_entry {
                    let file_path = entry.path();
                    
                    // only care about files, not folders
                    if file_path.is_file() {
                        let path_string = file_path.to_string_lossy().to_lowercase();
                        
                        // check if this looks like firmware
                        let looks_like_firmware = 
                            firmware_extensions.iter().any(|ext| path_string.ends_with(ext)) &&
                            (path_string.contains("ap_") || 
                             path_string.contains("boot") || 
                             path_string.contains("firmware") || 
                             path_string.contains("recovery") ||
                             path_string.contains("odin") || 
                             path_string.contains("stock"));
                        
                        if looks_like_firmware {
                            // get file size
                            let file_size = std::fs::metadata(&file_path)
                                .map(|m| m.len())
                                .unwrap_or(0);
                            
                            // figure out what type of file this is
                            let detected_type = self.what_kind_of_file(&path_string);
                            
                            found_files.push(FileInfo {
                                path: file_path.to_string_lossy().into_owned(),
                                file_type: detected_type.to_string(),
                                size: file_size,
                            });
                        }
                    }
                }
            }
        }
        
        found_files
    }
    
    // figure out what kind of firmware file this is
    fn what_kind_of_file(&self, filename: &str) -> &'static str {
        let name = filename.to_lowercase();
        
        if name.contains("ap_") && (name.ends_with(".tar.md5") || name.ends_with(".tar")) {
            "Samsung AP file"
        } else if name.ends_with(".tar.md5") || name.ends_with(".tar") {
            "ODIN tar file"
        } else if name.contains("boot") && name.ends_with(".img") {
            "Boot image"
        } else if name.contains("recovery") && name.ends_with(".img") {
            "Recovery image"
        } else if name.ends_with(".zip") {
            "OTA update zip"
        } else {
            "Unknown type"
        }
    }
    
    // placeholder for actual patching
    fn patch(&self, file_path: &str) -> String {
        format!("would patch {} here (not actually implemented yet)", file_path)
    }
}

// the gui part - what you actually see on screen
struct PatcherApp {
    patcher: FirmwarePatcher,
    files: Vec<FileInfo>,
    selected_file_index: usize,
    status_message: String,
    user_agreed_to_risks: bool,
    last_scan_time: String,
}

impl Default for PatcherApp {
    fn default() -> Self {
        let tool = FirmwarePatcher::new();
        let scanned_files = tool.scan();
        
        PatcherApp {
            patcher: tool,
            files: scanned_files,
            selected_file_index: 0,
            status_message: "Ready to go".to_string(),
            user_agreed_to_risks: false,
            last_scan_time: "just now".to_string(),
        }
    }
}

impl eframe::App for PatcherApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            // title
            ui.heading("🔧 Firmware Patcher Tool");
            ui.separator();
            
            // warning message
            ui.colored_label(egui::Color32::RED, "⚠️  WARNING: This can break your phone!");
            ui.label("If you mess up your phone, that's on you. I'm not responsible.");
            ui.add_space(10.0);
            
            // risk agreement checkbox
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.user_agreed_to_risks, "Yeah I understand the risks");
                if !self.user_agreed_to_risks {
                    ui.colored_label(egui::Color32::YELLOW, "(gotta check this box first)");
                }
            });
            ui.add_space(15.0);
            
            // file selection part
            ui.heading("📁 Pick a firmware file:");
            
            if self.files.is_empty() {
                ui.colored_label(egui::Color32::YELLOW, "No firmware files found here.");
                ui.label("Put one of these in this folder:");
                ui.label("• boot.img (extracted boot partition)");
                ui.label("• AP_*.tar.md5 (Samsung ODIN file)");
                ui.label("• *.zip (OTA update file)");
            } else {
                // dropdown to select file
                egui::ComboBox::from_label("")
                    .selected_text(
                        self.files.get(self.selected_file_index)
                            .map(|f| f.path.clone())
                            .unwrap_or_else(|| "pick one...".to_string())
                    )
                    .show_ui(ui, |ui| {
                        for (index, file) in self.files.iter().enumerate() {
                            ui.selectable_value(&mut self.selected_file_index, index, &file.path);
                        }
                    });
                
                // show info about selected file
                if let Some(file) = self.files.get(self.selected_file_index) {
                    ui.add_space(10.0);
                    ui.label(format!("📄 Type: {}", file.file_type));
                    ui.label(format!("📏 Size: {:.1} MB", file.size as f64 / 1_000_000.0));
                }
            }
            
            ui.add_space(20.0);
            
            // buttons at the bottom
            ui.horizontal(|ui| {
                // rescan button
                if ui.button("🔄 Rescan folder").clicked() {
                    self.files = self.patcher.scan();
                    self.last_scan_time = "just now".to_string();
                    self.status_message = format!("Rescanned, found {} files", self.files.len());
                }
                
                // patch button (only works if risks agreed to)
                let can_patch = self.user_agreed_to_risks && !self.files.is_empty();
                if ui.add_enabled(can_patch, egui::Button::new("🚀 Patch it!")).clicked() {
                    if let Some(file) = self.files.get(self.selected_file_index) {
                        self.status_message = self.patcher.patch(&file.path);
                    }
                }
                
                // exit button
                if ui.button("❌ Quit").clicked() {
                    std::process::exit(0);
                }
            });
            
            ui.add_space(15.0);
            
            // status area at bottom
            ui.heading("📊 What's happening:");
            ui.label(&self.status_message);
            ui.label(format!("Last scan: {}", self.last_scan_time));
            ui.label(format!("Files found: {}", self.files.len()));
            
            // help section that you can expand
            ui.collapsing("❓ How to use this thing", |ui| {
                ui.label("1. Put a firmware file in the same folder as this program");
                ui.label("2. Check the 'I understand risks' box above");
                ui.label("3. Pick your file from the dropdown");
                ui.label("4. Click the 'Patch it!' button");
                ui.label("");
                ui.label("This is just a demo - actual patching isn't implemented yet.");
            });
        });
    }
}

// main function that starts everything
fn main() -> Result<(), eframe::Error> {
    // window settings
    let window_options = eframe::NativeOptions {
        initial_window_size: Some(egui::vec2(500.0, 550.0)),
        ..Default::default()
    };
    
    // run the app
    eframe::run_native(
        "Firmware Patcher",
        window_options,
        Box::new(|_| Box::new(PatcherApp::default())),
    )
}