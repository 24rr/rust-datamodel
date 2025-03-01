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
    writeln!(&mut stdout, " Starting optimized scan...")?;
    stdout.flush()?;

    let total_start_time = Instant::now();
    
    
    
    
    
    
    
    
    colors.write_header(&mut stdout, "scan", Color::Yellow)?;
    writeln!(&mut stdout, " Searching for \"Graphics\"...")?;
    
    let graphics_results = mem.aob_scan_all("Graphics", true, 10);
    
    if graphics_results.is_empty() {
        let mut stderr = StandardStream::stderr(ColorChoice::Always);
        colors.write_header(&mut stderr, "error", Color::Red)?;
        writeln!(&mut stderr, " Failed to find \"Graphics\" string")?;
        
        
        colors.write_header(&mut stdout, "scan", Color::Yellow)?;
        writeln!(&mut stdout, " Searching for \"RenderView\"...")?;
        
        let render_view_results = mem.aob_scan_all("RenderView", true, 10);
        
        if render_view_results.is_empty() {
            colors.write_header(&mut stderr, "error", Color::Red)?;
            writeln!(&mut stderr, " Failed to find \"RenderView\" string")?;
            return Ok(());
        }
        
        
        if let Some(data_model) = process_render_pattern(&colors, &mut stdout, &mem, &render_view_results)? {
            report_data_model(&colors, &mut stdout, &mem, data_model, total_start_time)?;
        } else {
            colors.write_header(&mut stderr, "error", Color::Red)?;
            writeln!(&mut stderr, " Failed to find DataModel through RenderView")?;
        }
    } else {
        
        if let Some(data_model) = process_render_pattern(&colors, &mut stdout, &mem, &graphics_results)? {
            report_data_model(&colors, &mut stdout, &mem, data_model, total_start_time)?;
        } else {
            
            colors.write_header(&mut stdout, "scan", Color::Yellow)?;
            writeln!(&mut stdout, " Searching for \"RenderView\"...")?;
            
            let render_view_results = mem.aob_scan_all("RenderView", true, 10);
            
            if !render_view_results.is_empty() {
                if let Some(data_model) = process_render_pattern(&colors, &mut stdout, &mem, &render_view_results)? {
                    report_data_model(&colors, &mut stdout, &mem, data_model, total_start_time)?;
                } else {
                    let mut stderr = StandardStream::stderr(ColorChoice::Always);
                    colors.write_header(&mut stderr, "error", Color::Red)?;
                    writeln!(&mut stderr, " Failed to find DataModel through any method")?;
                }
            } else {
                let mut stderr = StandardStream::stderr(ColorChoice::Always);
                colors.write_header(&mut stderr, "error", Color::Red)?;
                writeln!(&mut stderr, " Failed to find any render patterns")?;
            }
        }
    }

    colors.write_header(&mut stdout, "SH3DF", Color::Magenta)?;
    writeln!(&mut stdout, " Scan complete!")?;
    
    writeln!(&mut stdout, "\nPress Enter to exit...")?;
    let _ = std::io::stdin().read_line(&mut String::new());

    process::close_handle(process_handle);
    Ok(())
}


fn process_render_pattern(
    colors: &TermColors,
    stdout: &mut StandardStream,
    mem: &Memory,
    results: &[usize]
) -> Result<Option<usize>, Box<dyn std::error::Error>> {
    colors.write_header(stdout, "found", Color::Green)?;
    writeln!(stdout, " Found {} occurrences", results.len())?;
    
    
    const MAX_SCAN_RANGE: usize = 0x2000; 
    const SCAN_STEP: usize = 8;
    
    for (_idx, &addr) in results.iter().enumerate().take(5) {
        
        let scan_start = if addr > MAX_SCAN_RANGE { addr - MAX_SCAN_RANGE } else { 0 };
        let scan_end = addr + MAX_SCAN_RANGE;
        
        for scan_addr in (scan_start..scan_end).step_by(SCAN_STEP) {
            if let Ok(ptr) = mem.read::<usize>(scan_addr) {
                if !is_valid_address(ptr) {
                    continue;
                }
                
                
                if let Ok(vtable_ptr) = mem.read::<usize>(ptr) {
                    if !is_valid_address(vtable_ptr) {
                        continue;
                    }
                    
                    
                    
                    if let Ok(fake_dm) = mem.read::<usize>(ptr + 0x120) {
                        if !is_valid_address(fake_dm) {
                            continue;
                        }
                        
                        
                        if let Ok(real_dm) = mem.read::<usize>(fake_dm + 0x1B8) {
                            if !is_valid_address(real_dm) {
                                continue;
                            }
                            
                            
                            if quick_validate_data_model(mem, real_dm)? {
                                colors.write_header(stdout, "found", Color::Green)?;
                                writeln!(stdout, " Found RenderView at: {}", format_address(ptr))?;
                                writeln!(stdout, " FakeDataModel at offset 0x120: {}", format_address(fake_dm))?;
                                writeln!(stdout, " RealDataModel at offset 0x1B8: {}", format_address(real_dm))?;
                                return Ok(Some(real_dm));
                            }
                        }
                    }
                    
                    
                    
                    let fake_offsets = [0x118, 0x128];
                    let real_offsets = [0x1A8, 0x1C0];
                    
                    for &fake_offset in &fake_offsets {
                        if let Ok(fake_dm) = mem.read::<usize>(ptr + fake_offset) {
                            if !is_valid_address(fake_dm) {
                                continue;
                            }
                            
                            for &real_offset in &real_offsets {
                                if let Ok(real_dm) = mem.read::<usize>(fake_dm + real_offset) {
                                    if !is_valid_address(real_dm) {
                                        continue;
                                    }
                                    
                                    if quick_validate_data_model(mem, real_dm)? {
                                        colors.write_header(stdout, "found", Color::Green)?;
                                        writeln!(stdout, " Found RenderView at: {}", format_address(ptr))?;
                                        writeln!(stdout, " FakeDataModel at offset 0x{:X}: {}", 
                                            fake_offset, format_address(fake_dm))?;
                                        writeln!(stdout, " RealDataModel at offset 0x{:X}: {}", 
                                            real_offset, format_address(real_dm))?;
                                        return Ok(Some(real_dm));
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


fn quick_validate_data_model(
    mem: &Memory,
    addr: usize
) -> Result<bool, Box<dyn std::error::Error>> {
    
    if let Ok(vtable_ptr) = mem.read::<usize>(addr) {
        if !is_valid_address(vtable_ptr) {
            return Ok(false);
        }
        
        
        
        let key_offsets = [0x40, 0x58, 0x70];
        
        for &offset in &key_offsets {
            if let Ok(child_ptr) = mem.read::<usize>(addr + offset) {
                if is_valid_address(child_ptr) {
                    if let Ok(child_vtable) = mem.read::<usize>(child_ptr) {
                        if is_valid_address(child_vtable) {
                            
                            return Ok(true);
                        }
                    }
                }
            }
        }
    }
    
    Ok(false)
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
    
    
    let key_offsets = [0x40, 0x48, 0x58, 0x70];
    
    for &offset in &key_offsets {
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