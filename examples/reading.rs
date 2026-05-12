use itaf::decoder::{ArchiveEntry, ItafDecoder};
use std::{fs::File, path::Path};

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <input_archive> <output_directory>", args[0]);
        std::process::exit(1);
    }

    let input_path = &args[1];
    let output_dir = Path::new(&args[2]);

    println!("Extracting {} to {}", input_path, output_dir.display());

    let file = File::open(input_path)?;
    let decoder = ItafDecoder::new(file)?;

    for entry_result in decoder.entries() {
        let mut entry = entry_result?;

        let safe_path = entry.enclosed_path();
        let target_path = output_dir.join(safe_path);

        match &mut entry {
            ArchiveEntry::Directory(_dir) => {
                println!("Dir:  {:?}", target_path);
                std::fs::create_dir_all(&target_path)?;
            }
            ArchiveEntry::File(file_entry) => {
                println!("File: {:?}", target_path);
                if let Some(parent) = target_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let mut out_file = File::create(&target_path)?;
                let bytes_copied = std::io::copy(file_entry, &mut out_file)?;

                if let Some(crc) = file_entry.crc64() {
                    println!("      -> Verified CRC64: {:016X}", crc);
                }

                if bytes_copied != file_entry.size() {
                    eprintln!(
                        "Warning: Wrote {} bytes, expected {}",
                        bytes_copied,
                        file_entry.size()
                    );
                }

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let meta = file_entry.metadata();
                    let perms = std::fs::Permissions::from_mode(meta.mode);
                    std::fs::set_permissions(&target_path, perms)?;
                }
            }
            ArchiveEntry::Symlink(sym) => {
                println!("Link: {:?} -> {:?}", target_path, sym.target());
                if let Some(parent) = target_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                #[cfg(unix)]
                std::os::unix::fs::symlink(sym.target(), &target_path)?;

                #[cfg(windows)]
                {
                    if sym.is_target_dir() {
                        std::os::windows::fs::symlink_dir(sym.target(), &target_path)?;
                    } else {
                        std::os::windows::fs::symlink_file(sym.target(), &target_path)?;
                    }
                }
            }
            ArchiveEntry::Hardlink(hl) => {
                println!("Hard: {:?} -> {:?}", target_path, hl.target());
                if let Some(parent) = target_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let resolved_target = output_dir.join(hl.enclosed_target());
                #[cfg(unix)]
                std::fs::hard_link(&resolved_target, &target_path)?;
                #[cfg(windows)]
                std::fs::hard_link(&resolved_target, &target_path)?;
            }
        }
    }

    println!("Extraction complete.");
    Ok(())
}
