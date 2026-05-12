use itaf::encoder::{EncoderOptions, ItafEncoder, Metadata};
use std::{fs::File, path::Path, time::SystemTime};

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <output_file> <input_path>...", args[0]);
        std::process::exit(1);
    }

    let output_path = &args[1];
    let input_paths = &args[2..];

    println!("Creating archive: {}", output_path);
    let file = File::create(output_path)?;

    let options = EncoderOptions::default();
    let mut encoder = ItafEncoder::new(file, options)?;

    for path_str in input_paths {
        let path = Path::new(path_str);
        if !path.exists() {
            eprintln!("Skipping missing path: {}", path_str);
            continue;
        }
        add_recursive(&mut encoder, path)?;
    }

    encoder.finish()?;
    println!("Done.");
    Ok(())
}

fn add_recursive(encoder: &mut ItafEncoder<File>, path: &Path) -> std::io::Result<()> {
    let fs_meta = std::fs::symlink_metadata(path)?;
    let file_type = fs_meta.file_type();

    let name = match path.file_name() {
        Some(n) => n.to_string_lossy(),
        None => return Ok(()),
    };

    let meta = Metadata {
        modified: fs_meta.modified().unwrap_or(SystemTime::now()),
        #[cfg(unix)]
        uid: std::os::unix::fs::MetadataExt::uid(&fs_meta) as u64,
        #[cfg(not(unix))]
        uid: 0,
        #[cfg(unix)]
        gid: std::os::unix::fs::MetadataExt::gid(&fs_meta) as u64,
        #[cfg(not(unix))]
        gid: 0,
        #[cfg(unix)]
        mode: std::os::unix::fs::MetadataExt::mode(&fs_meta),
        #[cfg(not(unix))]
        mode: 0o644,
    };

    if file_type.is_dir() {
        println!("Dir:  {}", path.display());
        encoder.enter_dir(&name, &meta)?;

        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            add_recursive(encoder, &entry.path())?;
        }

        encoder.exit_dir()?;
    } else if file_type.is_file() {
        println!("File: {}", path.display());
        let size = fs_meta.len();
        let mut f = File::open(path)?;
        encoder.add_file(&name, &meta, size, &mut f)?;
    } else if file_type.is_symlink() {
        println!("Link: {}", path.display());
        let target = std::fs::read_link(path)?;
        let target_str = target.to_string_lossy();
        encoder.add_symlink(&name, &target_str, false, &meta)?;
    }

    Ok(())
}
