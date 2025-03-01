mod memory;
mod process;
mod utils;

use termcolor::{Color, ColorChoice, StandardStream};
use memory::Memory;
use process::{get_process_id_by_name, get_module_base_address};
use utils::{format_address, TermColors};
use std::io::Write;
use std::time::Instant;


fn is_valid_address(addr: usize) -> bool {
    
    
    
    
    addr > 0x10000 && 
    addr % 4 == 0 && 
    addr < 0x00007FFFFFFEFFFF
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let colors = TermColors;
    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    
    utils::show_credits(&mut stdout)?;
    
    colors.write_header(&mut stdout, "init", Color::Yellow)?;
    writeln!(&mut stdout, " Searching for Roblox process...")?;
    stdout.flush()?;

    let process_id = match get_process_id_by_name("RobloxPlayerBeta.exe") {
        Some(id) => id,
        None => {
            let mut stderr = StandardStream::stderr(ColorChoice::Always);
            colors.write_header(&mut stderr, "error", Color::Red)?;
            writeln!(&mut stderr, " Failed to find Roblox process")?;
            return Ok(());
        }
    };

    colors.write_header(&mut stdout, "success", Color::Green)?;
    writeln!(&mut stdout, " Found Roblox process ID: {}", process_id)?;

    
    colors.write_header(&mut stdout, "init", Color::Yellow)?;
    writeln!(&mut stdout, " Acquiring process handle...")?;
    stdout.flush()?;

    let process_handle = match process::open_process(process_id) {
        Ok(handle) => handle,
        Err(e) => {
            let mut stderr = StandardStream::stderr(ColorChoice::Always);
            colors.write_header(&mut stderr, "error", Color::Red)?;
            writeln!(&mut stderr, " Failed to open process: {}", e)?;
            return Ok(());
        }
    };

    colors.write_header(&mut stdout, "success", Color::Green)?;
    writeln!(&mut stdout, " Process handle acquired")?;

    
    colors.write_header(&mut stdout, "init", Color::Yellow)?;
    writeln!(&mut stdout, " Getting base address...")?;
    stdout.flush()?;

    let base_address = match get_module_base_address(process_id, "RobloxPlayerBeta.exe") {
        Some(addr) => addr,
        None => {
            let mut stderr = StandardStream::stderr(ColorChoice::Always);
            colors.write_header(&mut stderr, "error", Color::Red)?;
            writeln!(&mut stderr, " Failed to get base address")?;
            return Ok(());
        }
    };

    colors.write_header(&mut stdout, "success", Color::Green)?;
    writeln!(&mut stdout, " Base address: {}", format_address(base_address))?;

    let mem = Memory::new(process_handle, base_address);

    
    colors.write_header(&mut stdout, "SH3DF", Color::Magenta)?;
    writeln!(&mut stdout, " Starting multi-strategy scan...")?;
    stdout.flush()?;

    let total_start_time = Instant::now();
    
    
    if let Some(data_model) = try_string_based_scan(&colors, &mut stdout, &mem)? {
        report_data_model(&colors, &mut stdout, &mem, data_model, total_start_time)?;
    } else if let Some(data_model) = try_scene_scan(&colors, &mut stdout, &mem)? {
        report_data_model(&colors, &mut stdout, &mem, data_model, total_start_time)?;
    } else if let Some(data_model) = try_workspace_scan(&colors, &mut stdout, &mem)? {
        report_data_model(&colors, &mut stdout, &mem, data_model, total_start_time)?;
    } else {
        
        colors.write_header(&mut stdout, "fallback", Color::Yellow)?;
        writeln!(&mut stdout, " Trying original RenderJob pattern...")?;
        
        let datamodel = mem.aob_scan_all("RenderJob(EarlyRendering;", false, 1);
        
        if !datamodel.is_empty() {
            const RENDERVIEW_OFFSET: usize = 0x1E8;
            
            let mut valid_dm = None;
            for dm_addr in &datamodel {
                if let Ok(_test_read) = mem.read::<[u8; 0x200]>(*dm_addr) {
                    let render_view = mem.read::<usize>(*dm_addr + RENDERVIEW_OFFSET);
                    match render_view {
                        Ok(rv_addr) if is_valid_address(rv_addr) => {
                            valid_dm = Some(*dm_addr);
                            break;
                        },
                        Err(e) => {
                            colors.write_header(&mut stdout, "warn", Color::Yellow)?;
                            writeln!(&mut stdout, " Invalid RenderView at {}: {}", 
                                format_address(*dm_addr + RENDERVIEW_OFFSET), e)?;
                            break;
                        },
                        _ => continue
                    }
                }
            }
            
            if let Some(dm_addr) = valid_dm {
                colors.write_header(&mut stdout, "found", Color::Green)?;
                writeln!(&mut stdout, " DataModel pattern at: {}", format_address(dm_addr))?;
                
                
                let potential_offsets = [0x1E8, 0x1E0, 0x1F0, 0x1D8, 0x1D0, 0x1F8, 0x200];
                
                let mut found_render_view = false;
                for &offset in &potential_offsets {
                    match mem.read::<usize>(dm_addr + offset) {
                        Ok(rv_addr) if is_valid_address(rv_addr) => {
                            colors.write_header(&mut stdout, "read", Color::Cyan)?;
                            writeln!(&mut stdout, " RenderView address at offset 0x{:X}: {}", 
                                offset, format_address(rv_addr))?;
                            
                            
                            if let Ok(_) = mem.read::<[u8; 0x100]>(rv_addr) {
                                found_render_view = true;
                                
                                
                                if let Some(data_model) = find_data_model_from_render_view(&colors, &mut stdout, &mem, rv_addr)? {
                                    report_data_model(&colors, &mut stdout, &mem, data_model, total_start_time)?;
                                    return Ok(());
                                }
                            }
                        },
                        _ => continue,
                    }
                }
                
                if !found_render_view {
                    let mut stderr = StandardStream::stderr(ColorChoice::Always);
                    colors.write_header(&mut stderr, "error", Color::Red)?;
                    writeln!(&mut stderr, " Could not find valid RenderView pointer")?;
                }
            } else {
                let mut stderr = StandardStream::stderr(ColorChoice::Always);
                colors.write_header(&mut stderr, "error", Color::Red)?;
                writeln!(&mut stderr, " No valid DataModel addresses found")?;
            }
        } else {
            let mut stderr = StandardStream::stderr(ColorChoice::Always);
            colors.write_header(&mut stderr, "error", Color::Red)?;
            writeln!(&mut stderr, " Failed to find DataModel with any method")?;
        }
    }

    colors.write_header(&mut stdout, "SH3DF", Color::Magenta)?;
    writeln!(&mut stdout, " Scan complete!")?;
    
    writeln!(&mut stdout, "\nPress Enter to exit...")?;
    let _ = std::io::stdin().read_line(&mut String::new());

    process::close_handle(process_handle);
    Ok(())
}


fn try_string_based_scan(
    colors: &TermColors,
    stdout: &mut StandardStream,
    mem: &Memory
) -> Result<Option<usize>, Box<dyn std::error::Error>> {
    colors.write_header(stdout, "strategy", Color::Blue)?;
    writeln!(stdout, " Trying string-based scan...")?;
    
    
    let string_patterns = [
        "DataModel",
        "RobloxDataModel",
        "Game.DataModel",
        "Workspace",
        "Players",
        "Lighting",
        "ReplicatedStorage",
        "ServerStorage",
        "StarterPack",
        "StarterGui",
        "StarterPlayer",
        "LocalizationService"
    ];
    
    for pattern in string_patterns.iter() {
        colors.write_header(stdout, "scan", Color::Yellow)?;
        writeln!(stdout, " Searching for string: \"{}\"", pattern)?;
        
        let results = mem.aob_scan_all(pattern, true, 10);
        if !results.is_empty() {
            colors.write_header(stdout, "found", Color::Green)?;
            writeln!(stdout, " Found {} occurrences of \"{}\"", results.len(), pattern)?;
            
            
            for (_idx, &addr) in results.iter().enumerate().take(5) {
                colors.write_header(stdout, "check", Color::Cyan)?;
                writeln!(stdout, " [{}/5] Checking around: {}", _idx + 1, format_address(addr))?;
                
                
                let scan_start = if addr > 0x1000 { addr - 0x1000 } else { 0 };
                let scan_end = addr + 0x1000;
                
                
                for scan_addr in (scan_start..scan_end).step_by(8) {
                    if let Ok(ptr) = mem.read::<usize>(scan_addr) {
                        if is_valid_address(ptr) {
                            
                            if let Ok(vtable_ptr) = mem.read::<usize>(ptr) {
                                if is_valid_address(vtable_ptr) {
                                    colors.write_header(stdout, "candidate", Color::Green)?;
                                    writeln!(stdout, " Potential object at: {}", format_address(ptr))?;
                                    
                                    
                                    if validate_as_data_model(mem, ptr)? {
                                        colors.write_header(stdout, "found", Color::Green)?;
                                        writeln!(stdout, " Validated as potential DataModel: {}", format_address(ptr))?;
                                        return Ok(Some(ptr));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    Ok(None)
}


fn try_workspace_scan(
    colors: &TermColors,
    stdout: &mut StandardStream,
    mem: &Memory
) -> Result<Option<usize>, Box<dyn std::error::Error>> {
    colors.write_header(stdout, "strategy", Color::Blue)?;
    writeln!(stdout, " Trying Workspace scan...")?;
    
    
    let workspace_strings = [
        "Workspace",
        "Terrain",
        "Camera",
        "Baseplate",
        "BaseplateTemplate"
    ];
    
    for pattern in workspace_strings.iter() {
        let results = mem.aob_scan_all(pattern, true, 10);
        if !results.is_empty() {
            colors.write_header(stdout, "found", Color::Green)?;
            writeln!(stdout, " Found {} occurrences of \"{}\"", results.len(), pattern)?;
            
            
            for (_idx, &addr) in results.iter().enumerate().take(5) {
                
                let scan_start = if addr > 0x1000 { addr - 0x1000 } else { 0 };
                
                for scan_addr in (scan_start..addr).step_by(8) {
                    if let Ok(ptr) = mem.read::<usize>(scan_addr) {
                        if ptr == addr {
                            
                            let potential_name_offset = scan_addr - 0x10; 
                            let potential_instance = potential_name_offset - 0x8; 
                            
                            if let Ok(vtable_ptr) = mem.read::<usize>(potential_instance) {
                                if is_valid_address(vtable_ptr) {
                                    
                                    if let Ok(parent_ptr) = mem.read::<usize>(potential_instance + 0x60) {
                                        if is_valid_address(parent_ptr) {
                                            
                                            if validate_as_data_model(mem, parent_ptr)? {
                                                colors.write_header(stdout, "found", Color::Green)?;
                                                writeln!(stdout, " Found DataModel as parent of \"{}\": {}", 
                                                    pattern, format_address(parent_ptr))?;
                                                return Ok(Some(parent_ptr));
                                            } else {
                                                
                                                if let Ok(grandparent_ptr) = mem.read::<usize>(parent_ptr + 0x60) {
                                                    if is_valid_address(grandparent_ptr) && validate_as_data_model(mem, grandparent_ptr)? {
                                                        colors.write_header(stdout, "found", Color::Green)?;
                                                        writeln!(stdout, " Found DataModel as grandparent of \"{}\": {}", 
                                                            pattern, format_address(grandparent_ptr))?;
                                                        return Ok(Some(grandparent_ptr));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    Ok(None)
}


fn try_scene_scan(
    colors: &TermColors,
    stdout: &mut StandardStream,
    mem: &Memory
) -> Result<Option<usize>, Box<dyn std::error::Error>> {
    colors.write_header(stdout, "strategy", Color::Blue)?;
    writeln!(stdout, " Trying Scene/Rendering scan...")?;
    
    
    let render_strings = [
        "RenderJob",
        "RenderSettings",
        "RenderView",
        "Graphics", 
        "GraphicsImpl",
        "DataModel::Render"
    ];
    
    for pattern in render_strings.iter() {
        let results = mem.aob_scan_all(pattern, true, 20);
        if !results.is_empty() {
            colors.write_header(stdout, "found", Color::Green)?;
            writeln!(stdout, " Found {} occurrences of \"{}\"", results.len(), pattern)?;
            
            for (_idx, &addr) in results.iter().enumerate().take(10) {
                
                let scan_start = if addr > 0x10000 { addr - 0x10000 } else { 0 };
                let scan_end = addr + 0x10000;
                
                
                for scan_addr in (scan_start..scan_end).step_by(8) {
                    if let Ok(ptr) = mem.read::<usize>(scan_addr) {
                        if is_valid_address(ptr) {
                            
                            if let Ok(vtable_ptr) = mem.read::<usize>(ptr) {
                                if is_valid_address(vtable_ptr) {
                                    
                                    colors.write_header(stdout, "check", Color::Cyan)?;
                                    writeln!(stdout, " Checking potential render object: {}", format_address(ptr))?;
                                    
                                    
                                    if let Some(data_model) = find_data_model_from_render_view(colors, stdout, mem, ptr)? {
                                        return Ok(Some(data_model));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    Ok(None)
}


fn validate_as_data_model(
    mem: &Memory,
    addr: usize
) -> Result<bool, Box<dyn std::error::Error>> {
    
    if let Ok(vtable_ptr) = mem.read::<usize>(addr) {
        if !is_valid_address(vtable_ptr) {
            return Ok(false);
        }
        
        
        let child_offsets = [0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0x90, 0x98, 0xA0];
        let mut valid_children = 0;
        
        for &offset in &child_offsets {
            if let Ok(child_ptr) = mem.read::<usize>(addr + offset) {
                if is_valid_address(child_ptr) {
                    
                    if let Ok(child_vtable) = mem.read::<usize>(child_ptr) {
                        if is_valid_address(child_vtable) {
                            valid_children += 1;
                            
                            
                            if valid_children >= 3 {
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }
    }
    
    Ok(false)
}


fn find_data_model_from_render_view(
    colors: &TermColors,
    stdout: &mut StandardStream,
    mem: &Memory,
    render_view: usize
) -> Result<Option<usize>, Box<dyn std::error::Error>> {
    
    let potential_offsets = [0x108, 0x110, 0x118, 0x120, 0x128, 0x130, 0x138, 0x140, 0x148, 0x150];
    
    for &offset in &potential_offsets {
        if let Ok(ptr) = mem.read::<usize>(render_view + offset) {
            if is_valid_address(ptr) {
                colors.write_header(stdout, "check", Color::Cyan)?;
                writeln!(stdout, " Checking offset 0x{:X} -> {}", offset, format_address(ptr))?;
                
                
                if let Ok(vtable_ptr) = mem.read::<usize>(ptr) {
                    if is_valid_address(vtable_ptr) {
                        
                        
                        let dm_offsets = [0x1A0, 0x1A8, 0x1B0, 0x1B8, 0x1C0, 0x1C8, 0x1D0, 0x1D8];
                        
                        for &dm_offset in &dm_offsets {
                            if let Ok(dm_ptr) = mem.read::<usize>(ptr + dm_offset) {
                                if is_valid_address(dm_ptr) {
                                    if let Ok(dm_vtable) = mem.read::<usize>(dm_ptr) {
                                        if is_valid_address(dm_vtable) {
                                            
                                            if validate_as_data_model(mem, dm_ptr)? {
                                                colors.write_header(stdout, "found", Color::Green)?;
                                                writeln!(stdout, " Found RealDataModel at offset 0x{:X} -> {}", 
                                                    dm_offset, format_address(dm_ptr))?;
                                                writeln!(stdout, " Via FakeDataModel at offset 0x{:X} -> {}", 
                                                    offset, format_address(ptr))?;
                                                return Ok(Some(dm_ptr));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    Ok(None)
}


fn report_data_model(
    colors: &TermColors,
    stdout: &mut StandardStream,
    mem: &Memory,
    data_model: usize,
    start_time: Instant
) -> Result<(), Box<dyn std::error::Error>> {
    colors.write_header(stdout, "success", Color::Green)?;
    writeln!(stdout, " Found DataModel at: {}", format_address(data_model))?;
    
    
    if let Ok(vtable) = mem.read::<usize>(data_model) {
        colors.write_header(stdout, "vtable", Color::Cyan)?;
        writeln!(stdout, " DataModel VTable: {}", format_address(vtable))?;
    }
    
    
    let member_offsets = [0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0x90, 0x98, 0xA0];
    
    for &offset in &member_offsets {
        if let Ok(ptr) = mem.read::<usize>(data_model + offset) {
            if is_valid_address(ptr) {
                if let Ok(vtable) = mem.read::<usize>(ptr) {
                    if is_valid_address(vtable) {
                        
                        
                        if let Ok(name_ptr) = mem.read::<usize>(ptr + 0x10) {
                            if is_valid_address(name_ptr) {
                                
                                let mut buffer = [0u8; 32];
                                if let Ok(_) = mem.read_raw(name_ptr, &mut buffer) {
                                    
                                    for i in 0..buffer.len() {
                                        if buffer[i] == 0 {
                                            break;
                                        }
                                        if !buffer[i].is_ascii_graphic() && buffer[i] != b' ' {
                                            buffer[i] = 0;
                                            break;
                                        }
                                    }
                                    
                                    
                                    if let Ok(name) = std::str::from_utf8(&buffer) {
                                        let name = name.trim_matches(char::from(0));
                                        if !name.is_empty() {
                                            colors.write_header(stdout, "member", Color::Cyan)?;
                                            writeln!(stdout, " Object at offset 0x{:X}: {} ({})", 
                                                offset, name, format_address(ptr))?;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    
    let duration = start_time.elapsed();
    colors.write_header(stdout, "time", Color::Yellow)?;
    writeln!(stdout, " Operation took {:.3}ms ({:.3}s)", 
        duration.as_millis(), duration.as_secs_f64())?;
    
    
    colors.write_header(stdout, "info", Color::Blue)?;
    writeln!(stdout, " For future use, you can directly scan for VTable or other key addresses")?;
    
    Ok(())
}