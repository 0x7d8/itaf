use itaf::raw_decoder::{RawDecoder, RawRecord};
use std::{
    fs::File,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <input_archive>", args[0]);
        std::process::exit(1);
    }

    let input_path = &args[1];
    let file = File::open(input_path)?;

    println!(" INSPECTING: {}", input_path);

    let decoder = RawDecoder::new(file)?;

    println!("GLOBAL HEADER:");
    println!("  Base Timestamp: {} (Epoch ns)", decoder.base_timestamp);
    println!("");

    let mut path_stack: Vec<String> = Vec::new();
    let mut current_time_base = decoder.base_timestamp;
    let mut current_uid = 0;
    let mut current_gid = 0;
    let mut current_mode = 0o644;

    let mut op_count = 0;

    for record_res in decoder.records() {
        let record = record_res?;
        op_count += 1;

        println!("OP #{:04}:", op_count);

        match record {
            RawRecord::File(entry) => {
                println!("  [INSTRUCTION: FILE]");
                println!("    Raw Name:   '{}'", entry.name);
                println!("    Size:       {} bytes", entry.size);
                println!("    Time Delta: {}", entry.time_delta_ns);

                let full_path = resolve_path(&path_stack, &entry.name);
                let abs_time = resolve_time(current_time_base, entry.time_delta_ns);

                println!("  [RESOLVED CONTEXT]");
                println!("    Full Path:  {:?}", full_path);
                println!("    Abs Time:   {:?}", abs_time);
                println!(
                    "    Attributes: UID={}, GID={}, Mode={:o}",
                    current_uid, current_gid, current_mode
                );
            }
            RawRecord::DirEnter {
                name,
                time_delta_ns,
            } => {
                println!("  [INSTRUCTION: DIR_ENTER]");
                println!("    Dir Name:   '{}'", name);
                println!("    Time Delta: {}", time_delta_ns);

                path_stack.push(name.clone());
                let full_path = resolve_path(&path_stack, "");
                let abs_time = resolve_time(current_time_base, time_delta_ns);

                println!("  [STATE UPDATE]");
                println!("    Pushed Dir. New CWD: {:?}", full_path);
                println!("    Dir Time:   {:?}", abs_time);
            }
            RawRecord::DirExit => {
                println!("  [INSTRUCTION: DIR_EXIT]");

                let old = path_stack.pop();
                let full_path = resolve_path(&path_stack, "");

                println!("  [STATE UPDATE]");
                println!("    Popped Dir: '{:?}'. Back to: {:?}", old, full_path);
            }
            RawRecord::Meta { has_crc, time_base } => {
                println!("  [INSTRUCTION: META]");
                println!("    Set CRC:    {}", has_crc);
                println!("    Set Base:   {}", time_base);

                current_time_base = time_base;

                println!("  [STATE UPDATE]");
                println!("    Time Base updated. Future deltas relative to this.");
            }
            RawRecord::UnixAttr { uid, gid, mode } => {
                println!("  [INSTRUCTION: UNIX_ATTR]");
                println!("    UID:  {}", uid);
                println!("    GID:  {}", gid);
                println!("    Mode: {:o}", mode);

                current_uid = uid;
                current_gid = gid;
                current_mode = mode;

                println!("  [STATE UPDATE]");
                println!("    Ownership/Permissions updated for subsequent files.");
            }
            RawRecord::Symlink {
                name,
                target,
                is_dir,
                time_delta_ns,
            } => {
                println!("  [INSTRUCTION: SYMLINK]");
                println!("    Name:       '{}'", name);
                println!("    Target:     '{}'", target);
                println!("    Is Dir:     {}", is_dir);
                println!("    Time Delta: {}", time_delta_ns);

                let full_path = resolve_path(&path_stack, &name);
                let abs_time = resolve_time(current_time_base, time_delta_ns);

                println!("  [RESOLVED]");
                println!("    Link Path:  {:?}", full_path);
                println!("    Sym Time:   {:?}", abs_time);
            }
            RawRecord::Hardlink {
                name,
                target,
                time_delta_ns,
            } => {
                println!("  [INSTRUCTION: HARDLINK]");
                println!("    Name:       '{}'", name);
                println!("    Target:     '{}'", target);
                println!("    Time Delta: {}", time_delta_ns);

                let full_path = resolve_path(&path_stack, &name);
                let abs_time = resolve_time(current_time_base, time_delta_ns);

                println!("  [RESOLVED]");
                println!("    Link Path:  {:?}", full_path);
                println!("    Hard Time:  {:?}", abs_time);
            }
            RawRecord::Ext { type_id, data } => {
                println!("  [INSTRUCTION: EXT]");
                println!("    Type ID:    {}", type_id);
                println!("    Data Len:   {} bytes", data.len());
            }
        }
        println!("------------------------------------------------------------");
    }

    println!("Done. Total operations: {}", op_count);
    Ok(())
}

fn resolve_path(stack: &[String], name: &str) -> PathBuf {
    let mut p = PathBuf::from("/");
    for seg in stack {
        p.push(seg);
    }
    if !name.is_empty() {
        p.push(name);
    }
    p
}

fn resolve_time(base: i64, delta: i64) -> SystemTime {
    let ns = base.wrapping_add(delta);
    if ns >= 0 {
        UNIX_EPOCH + Duration::from_nanos(ns as u64)
    } else {
        UNIX_EPOCH - Duration::from_nanos((-ns) as u64)
    }
}
