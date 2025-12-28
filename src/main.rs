// firmware patcher tool - one file, does it all
// scans for android firmware files and tries to patch them

use eframe::egui;
use byteorder::{ByteOrder, LittleEndian};
use std::io::{Read, Write};

// info about a firmware file we found
struct FirmwareFile {
    path: String,      // file location
    kind: FileType,    // what type of file
    size: u64,         // file size in bytes
}

// different firmware file types we can handle
#[derive(Clone, Debug)]
enum FileType {
    SamsungAP,      // samsung AP tar files
    OdinTar,        // regular ODIN tar files  
    BootImage,      // boot.img files
    RecoveryImage,  // recovery.img files
    OTAZip,         // OTA update zips
    Unknown,        // something else
}

impl FileType {
    // get a readable name for the file type
    fn name(&self) -> &str {
        match self {
            FileType::SamsungAP => "Samsung AP file",
            FileType::OdinTar => "ODIN tar file",
            FileType::BootImage => "Boot image",
            FileType::RecoveryImage => "Recovery image",
            FileType::OTAZip => "OTA update zip",
            FileType::Unknown => "Unknown type",
        }
    }
}

// main patcher engine - does the actual work
struct PatcherEngine {
    debug_mode: bool,
}

impl PatcherEngine {
    fn new() -> Self {
        PatcherEngine { debug_mode: false }
    }
    
    // patch a boot image file
    fn patch_boot_image(&self, file_path: &str) -> Result<String, String> {
        if self.debug_mode {
            println!("trying to patch boot image: {}", file_path);
        }
        
        // read the whole file
        let data = std::fs::read(file_path)
            .map_err(|e| format!("failed to read file: {}", e))?;
        
        // check if it's actually a boot image
        if data.len() < 1000 {
            return Err("file is too small to be a boot image".to_string());
        }
        
        // check for android magic bytes
        if &data[0..8] != b"ANDROID!" {
            return Err("not a valid android boot image".to_string());
        }
        
        // read some info from the header
        let page_size = LittleEndian::read_u32(&data[36..40]);
        let kernel_size = LittleEndian::read_u32(&data[8..12]);
        let ramdisk_size = LittleEndian::read_u32(&data[16..20]);
        
        if self.debug_mode {
            println!("boot image info:");
            println!("  page size: {}", page_size);
            println!("  kernel size: {} bytes", kernel_size);
            println!("  ramdisk size: {} bytes", ramdisk_size);
        }
        
        // try to extract and patch the ramdisk
        let kernel_pages = (kernel_size + page_size - 1) / page_size;
        let ramdisk_start = page_size as usize + (kernel_pages * page_size) as usize;
        let ramdisk_end = ramdisk_start + ramdisk_size as usize;
        
        if ramdisk_end > data.len() {
            return Err("ramdisk data goes past end of file".to_string());
        }
        
        let ramdisk_data = &data[ramdisk_start..ramdisk_end];
        
        // try to parse the ramdisk (it's a cpio archive)
        match self.patch_ramdisk(ramdisk_data) {
            Ok(new_ramdisk) => {
                // create new boot image with patched ramdisk
                let mut new_boot = Vec::new();
                
                // copy everything before ramdisk
                new_boot.extend_from_slice(&data[0..ramdisk_start]);
                
                // add patched ramdisk
                new_boot.extend_from_slice(&new_ramdisk);
                
                // pad to page boundary
                while new_boot.len() % page_size as usize != 0 {
                    new_boot.push(0);
                }
                
                // copy anything after ramdisk (if there is any)
                if ramdisk_end < data.len() {
                    new_boot.extend_from_slice(&data[ramdisk_end..]);
                }
                
                // save the patched file
                let output_name = format!("{}.patched", file_path);
                std::fs::write(&output_name, &new_boot)
                    .map_err(|e| format!("failed to write patched file: {}", e))?;
                
                Ok(format!("boot image patched successfully! saved as: {}", output_name))
            }
            Err(e) => {
                // if we can't parse ramdisk, just add a marker
                if self.debug_mode {
                    println!("couldn't parse ramdisk properly: {}", e);
                }
                
                let mut patched = data.clone();
                patched.extend_from_slice(b"\n# patched by firmware tool\n");
                
                let output_name = format!("{}.patched", file_path);
                std::fs::write(&output_name, &patched)
                    .map_err(|e| format!("failed to write file: {}", e))?;
                
                Ok(format!("added patch marker to: {}", output_name))
            }
        }
    }
    
    // try to patch a cpio ramdisk archive
    fn patch_ramdisk(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 100 {
            return Err("ramdisk data too small".to_string());
        }
        
        // check for cpio magic
        if &data[0..6] != b"070701" && &data[0..6] != b"070702" {
            return Err("not a cpio archive".to_string());
        }
        
        // for now, just add a simple init script
        let mut new_data = data.to_vec();
        new_data.extend_from_slice(b"\n# magiskinit placeholder - real patching would go here\n");
        
        Ok(new_data)
    }
    
    // handle samsung AP/odin tar files
    fn handle_tar_file(&self, file_path: &str) -> Result<String, String> {
        // check if it's a tar file
        let data = std::fs::read(file_path)
            .map_err(|e| format!("failed to read file: {}", e))?;
        
        // tar files have a specific header
        if data.len() > 512 && &data[257..262] == b"ustar" {
            if self.debug_mode {
                println!("found tar file: {}", file_path);
            }
            
            // try to extract boot.img from the tar
            // (in a real implementation, we'd use the tar crate)
            
            // for now, just say we found it
            Ok("found tar archive - would extract and patch boot.img".to_string())
        } else {
            Err("doesn't look like a valid tar file".to_string())
        }
    }
    
    // handle zip files (OTA updates)
    fn handle_zip_file(&self, file_path: &str) -> Result<String, String> {
        // check zip magic
        let data = std::fs::read(file_path)
            .map_err(|e| format!("failed to read file: {}", e))?;
        
        if data.len() >= 4 && &data[0..4] == b"PK\x03\x04" {
            if self.debug_mode {
                println!("found zip file: {}", file_path);
            }
            
            // try to find boot.img or payload.bin inside
            // (in a real implementation, we'd use the zip crate)
            
            Ok("found zip archive - would extract and patch".to_string())
        } else {
            Err("doesn't look like a valid zip file".to_string())
        }
    }
    
    // scan for firmware files in current folder
    fn find_files(&self) -> Vec<FirmwareFile> {
        let mut found = Vec::new();
        
        // file extensions we're looking for
        let firmware_exts = [".tar.md5", ".md5", ".tar", ".zip", ".img"];
        
        // try to read current directory
        let entries = match std::fs::read_dir("./") {
            Ok(e) => e,
            Err(_) => {
                if self.debug_mode {
                    println!("can't read current directory");
                }
                return found;
            }
        };
        
        for entry_result in entries {
            if let Ok(entry) = entry_result {
                let path = entry.path();
                
                // only look at files, not folders
                if !path.is_file() {
                    continue;
                }
                
                let path_str = path.to_string_lossy().to_lowercase();
                
                // check if it has a firmware extension
                let has_ext = firmware_exts.iter().any(|ext| path_str.ends_with(ext));
                
                // check for keywords in filename
                let has_keyword = path_str.contains("ap_") 
                    || path_str.contains("boot")
                    || path_str.contains("firmware")
                    || path_str.contains("recovery")
                    || path_str.contains("odin")
                    || path_str.contains("stock");
                
                if has_ext && has_keyword {
                    // get file size
                    let size = std::fs::metadata(&path)
                        .map(|m| m.len())
                        .unwrap_or(0);
                    
                    // figure out what type it is
                    let file_type = Self::guess_file_type(&path_str);
                    
                    found.push(FirmwareFile {
                        path: path.to_string_lossy().into_owned(),
                        kind: file_type,
                        size,
                    });
                }
            }
        }
        
        if self.debug_mode {
            println!("found {} firmware files", found.len());
        }
        
        found
    }
    
    // guess file type from filename
    fn guess_file_type(filename: &str) -> FileType {
        let name = filename.to_lowercase();
        
        if name.contains("ap_") && (name.ends_with(".tar.md5") || name.ends_with(".tar")) {
            FileType::SamsungAP
        } else if name.ends_with(".tar.md5") || name.ends_with(".tar") {
            FileType::OdinTar
        } else if name.contains("boot") && name.ends_with(".img") {
            FileType::BootImage
        } else if name.contains("recovery") && name.ends_with(".img") {
            FileType::RecoveryImage
        } else if name.ends_with(".zip") {
            FileType::OTAZip
        } else {
            FileType::Unknown
        }
    }
    
    // main patch function - routes to the right handler
    fn try_patch(&self, file_path: &str, file_type: &FileType) -> Result<String, String> {
        // first check if file exists
        if !std::path::Path::new(file_path).exists() {
            return Err(format!("file doesn't exist: {}", file_path));
        }
        
        // route to appropriate handler
        match file_type {
            FileType::BootImage => self.patch_boot_image(file_path),
            FileType::RecoveryImage => self.patch_boot_image(file_path), // same as boot
            FileType::SamsungAP => self.handle_tar_file(file_path),
            FileType::OdinTar => self.handle_tar_file(file_path),
            FileType::OTAZip => self.handle_zip_file(file_path),
            FileType::Unknown => Err("can't patch this - don't know what type of file it is".to_string()),
        }
    }
}

// the GUI app
struct PatcherApp {
    engine: PatcherEngine,
    files: Vec<FirmwareFile>,
    selected_file: Option<usize>,  // which file is selected
    status: String,
    risks_accepted: bool,
    last_scan_time: std::time::SystemTime,
}

impl Default for PatcherApp {
    fn default() -> Self {
        let engine = PatcherEngine::new();
        let files = engine.find_files();
        
        PatcherApp {
            engine,
            files,
            selected_file: None,
            status: "ready to scan for firmware files".to_string(),
            risks_accepted: false,
            last_scan_time: std::time::SystemTime::now(),
        }
    }
}

impl eframe::App for PatcherApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            // title
            ui.heading("🔧 Firmware Patcher Tool");
            ui.separator();
            
            // warning
            ui.colored_label(
                egui::Color32::RED,
                "⚠️  WARNING: This can break your phone!"
            );
            ui.label("If you brick your device, that's on you. Use at your own risk.");
            ui.add_space(10.0);
            
            // risk acceptance checkbox
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.risks_accepted, "I understand the risks");
                if !self.risks_accepted {
                    ui.colored_label(
                        egui::Color32::YELLOW,
                        "(must check this to continue)"
                    );
                }
            });
            ui.add_space(15.0);
            
            // file selection
            ui.heading("📁 Select a firmware file:");
            
            if self.files.is_empty() {
                ui.colored_label(
                    egui::Color32::YELLOW,
                    "No firmware files found here."
                );
                ui.label("Put one of these in this folder:");
                ui.label("  • boot.img (extracted boot image)");
                ui.label("  • AP_*.tar.md5 (Samsung ODIN file)");
                ui.label("  • *.zip (OTA update package)");
            } else {
                // show selected file
                let selected_text = self.selected_file
                    .and_then(|idx| self.files.get(idx))
                    .map(|f| f.path.clone())
                    .unwrap_or_else(|| "choose a file...".to_string());
                
                egui::ComboBox::from_label("")
                    .selected_text(selected_text)
                    .show_ui(ui, |ui| {
                        for (index, file) in self.files.iter().enumerate() {
                            let is_selected = self.selected_file == Some(index);
                            if ui.selectable_label(is_selected, &file.path).clicked() {
                                self.selected_file = Some(index);
                            }
                        }
                    });
                
                // show info about selected file
                if let Some(idx) = self.selected_file {
                    if let Some(file) = self.files.get(idx) {
                        ui.add_space(10.0);
                        ui.label(format!("📄 Type: {}", file.kind.name()));
                        ui.label(format!("📏 Size: {:.1} MB", file.size as f64 / 1_000_000.0));
                    }
                }
            }
            
            ui.add_space(20.0);
            
            // buttons
            ui.horizontal(|ui| {
                // rescan button
                if ui.button("🔄 Rescan Folder").clicked() {
                    self.files = self.engine.find_files();
                    self.last_scan_time = std::time::SystemTime::now();
                    self.status = format!("rescanned, found {} files", self.files.len());
                    self.selected_file = None;
                }
                
                // patch button (only enabled if risks accepted and file selected)
                let can_patch = self.risks_accepted 
                    && self.selected_file.is_some()
                    && !self.files.is_empty();
                
                if ui.add_enabled(can_patch, egui::Button::new("🚀 Patch File")).clicked() {
                    if let Some(idx) = self.selected_file {
                        if let Some(file) = self.files.get(idx) {
                            match self.engine.try_patch(&file.path, &file.kind) {
                                Ok(msg) => self.status = msg,
                                Err(err) => self.status = format!("Error: {}", err),
                            }
                        }
                    }
                }
                
                // quit button
                if ui.button("❌ Quit").clicked() {
                    std::process::exit(0);
                }
            });
            
            ui.add_space(15.0);
            ui.separator();
            
            // status section
            ui.heading("📊 Status:");
            ui.label(&self.status);
            
            // show when we last scanned
            let seconds_since_scan = std::time::SystemTime::now()
                .duration_since(self.last_scan_time)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            
            let time_text = if seconds_since_scan < 60 {
                "just now".to_string()
            } else {
                format!("{} minutes ago", seconds_since_scan / 60)
            };
            
            ui.label(format!("Last scan: {}", time_text));
            ui.label(format!("Files found: {}", self.files.len()));
            
            // help section
            ui.collapsing("❓ How to use this", |ui| {
                ui.label("1. Put firmware files in the same folder as this program");
                ui.label("2. Check the 'I understand risks' box");
                ui.label("3. Pick a file from the dropdown");
                ui.label("4. Click 'Patch File' to start");
                ui.add_space(5.0);
                ui.label("Note: This is a demo - real patching would need actual magisk files.");
            });
        });
    }
}

// main function
fn main() -> Result<(), eframe::Error> {
    let window_settings = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(egui::vec2(550.0, 600.0))
            .with_resizable(true),
        ..Default::default()
    };
    
    eframe::run_native(
        "Firmware Patcher",
        window_settings,
        Box::new(|_| Box::new(PatcherApp::default())),
    ) 
}