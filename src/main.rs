use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use colored::*;
use regex::bytes::Regex;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

// ── File signatures ──────────────────────────────────────────────────────────
const PNG_SIG: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
const JPG_SIG: &[u8] = &[0xFF, 0xD8, 0xFF];
const JPG_EOI: &[u8] = &[0xFF, 0xD9];
const GIF87_SIG: &[u8] = b"GIF87a";
const GIF89_SIG: &[u8] = b"GIF89a";
const ZIP_LOCAL_SIG: &[u8] = &[b'P', b'K', 0x03, 0x04];
const ZIP_EOCD_SIG: &[u8] = &[b'P', b'K', 0x05, 0x06];
const ZIP_SPANNED_SIG: &[u8] = &[b'P', b'K', 0x07, 0x08];
const RAR_SIG: &[u8] = &[b'R', b'a', b'r', b'!', 0x1A, 0x07];
const PDF_SIG: &[u8] = b"%PDF";
const PE_SIG: &[u8] = b"MZ";
const PE_HEADER_SIG: &[u8] = &[b'P', b'E', 0x00, 0x00];
const ELF_SIG: &[u8] = &[0x7F, b'E', b'L', b'F'];
const SEVEN_ZIP_SIG: &[u8] = &[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C];
const BZ2_SIG: &[u8] = b"BZh";
const GZIP_SIG: &[u8] = &[0x1F, 0x8B];
const XZ_SIG: &[u8] = &[0xFD, b'7', b'z', b'X', b'Z', 0x00];
const LZ4_SIG: &[u8] = &[0x04, 0x22, 0x4D, 0x18];
const CAB_SIG: &[u8] = b"MSCF";
const ISO_SIG: &[u8] = b"CD001";
const DMG_SIG: &[u8] = &[0x78, 0x01, 0x73, 0x0D, 0x62, 0x62, 0x60];
const MACH_O_SIG_32: &[u8] = &[0xFE, 0xED, 0xFA, 0xCE];
const MACH_O_SIG_64: &[u8] = &[0xFE, 0xED, 0xFA, 0xCF];
const MACH_O_SIG_32_REV: &[u8] = &[0xCE, 0xFA, 0xED, 0xFE];
const MACH_O_SIG_64_REV: &[u8] = &[0xCF, 0xFA, 0xED, 0xFE];
const RIFF_SIG: &[u8] = b"RIFF";
const WEBP_SIG: &[u8] = b"WEBP";

// ── CLI args ─────────────────────────────────────────────────────────────────
#[derive(Parser, Debug)]
#[command(
    name = "StegoRusting",
    version = "0.2.0",
    about = "A general-purpose CTF/stego scanner for strings, regex, hex patterns, metadata, and appended/embedded files"
)]
struct Args {
    /// Target file to analyze
    file: PathBuf,

    /// Search for a literal string in the file bytes. Can be repeated. E.g. --word "flag{"
    #[arg(long)]
    word: Vec<String>,

    /// Search by regex on the raw bytes. Can be repeated. E.g. --regex "flag\\{[^}]+\\}"
    #[arg(long)]
    regex: Vec<String>,

    /// Wordlist file with one literal pattern per line (blank lines and # comments ignored)
    #[arg(long)]
    wordlist: Option<PathBuf>,

    /// Search for a hex pattern. E.g. --hex "66 6c 61 67 7b"
    #[arg(long)]
    hex: Vec<String>,

    /// Automatically extract embedded blobs without prompting
    #[arg(long)]
    extract: bool,

    /// Output directory for extractions
    #[arg(long, default_value = "stegorusting_output")]
    out: PathBuf,

    /// Try to parse and extract blobs recursively from extracted files
    #[arg(long)]
    recursive: bool,

    /// Skip confirmation prompts
    #[arg(long)]
    yes: bool,

    /// Disable ANSI colors (useful for old PowerShell / cmd)
    #[arg(long)]
    no_color: bool,
}

// ── Types ────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, PartialEq, Eq)]
enum FileType {
    Png,
    Jpeg,
    Gif,
    Zip,
    Rar,
    Pdf,
    Pe,
    Elf,
    SevenZip,
    Bzip2,
    Gzip,
    Xz,
    Lz4,
    Cab,
    Iso,
    Dmg,
    MachO,
    Riff,
    WebP,
    Unknown,
}

#[derive(Debug)]
struct Finding {
    kind: String,
    label: String,
    offset: usize,
    preview: String,
}

#[derive(Debug)]
struct EmbeddedBlob {
    file_type: FileType,
    offset: usize,
    signature: &'static str,
}

// ── Main ─────────────────────────────────────────────────────────────────────
fn main() {
    let args = Args::parse();

    if args.no_color || env::var_os("NO_COLOR").is_some() {
        colored::control::set_override(false);
    }

    banner();

    let data = match fs::read(&args.file) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("{} Error reading file: {e}", "[-]".red().bold());
            std::process::exit(1);
        }
    };

    print_ok(&format!("File    : {}", args.file.display()));
    print_ok(&format!("Size    : {} bytes", data.len()));

    let file_type = detect_file_type(&data);
    print_ok(&format!("Detected: {:?}", file_type));

    // ── Stage 1: Hex / Strings / Regex / Wordlists ──────────────────────────
    stage_header(1, "HEX / STRINGS / REGEX / WORDLISTS");

    let mut findings: Vec<Finding> = Vec::new();
    let mut words = args.word.clone();

    if let Some(wordlist_path) = &args.wordlist {
        match read_wordlist(wordlist_path) {
            Ok(mut loaded) => words.append(&mut loaded),
            Err(e) => eprintln!("{} Error reading wordlist: {e}", "[!]".yellow().bold()),
        }
    }

    // Default wordlist if nothing specific provided
    if words.is_empty() && args.regex.is_empty() && args.hex.is_empty() {
        words.extend(default_search_words());
    }

    for word in &words {
        findings.extend(search_literal(&data, word.as_bytes(), &format!("word:{word}")));
    }

    for hx in &args.hex {
        match parse_hex_pattern(hx) {
            Ok(pattern) => findings.extend(search_literal(&data, &pattern, &format!("hex:{hx}"))),
            Err(e) => eprintln!("{} Invalid hex pattern '{}': {e}", "[!]".yellow().bold(), hx),
        }
    }

    for rx in &args.regex {
        match Regex::new(rx) {
            Ok(re) => findings.extend(search_regex(&data, &re, rx)),
            Err(e) => eprintln!("{} Invalid regex '{}': {e}", "[!]".yellow().bold(), rx),
        }
    }

    // Also run built-in heuristic searches
    findings.extend(find_base64_candidates(&data));
    findings.extend(find_hex_candidates(&data));

    print_findings(&findings);

    // ── Stage 2: Metadata / EXIF / XMP / Comments ───────────────────────────
    stage_header(2, "METADATA / EXIF / XMP / COMMENTS");
    analyze_metadata(&file_type, &data);

    println!();
    if !args.yes
        && !ask_yes_no(&format!(
            "{}",
            "[?] Proceed to structural analysis and hidden-file search?"
                .yellow()
                .bold()
        ))
    {
        print_warn("Structural analysis skipped by user.");
        return;
    }

    // ── Stage 3: Structure / Stego / Embedded files ─────────────────────────
    stage_header(3, "STRUCTURE / STEGO / EMBEDDED FILES");
    analyze_format_anomalies(&file_type, &data);

    let embedded = find_embedded_files(&data);
    if embedded.is_empty() {
        print_info("No obvious embedded files found by magic-byte scanning.");
    } else {
        print_warn("Possible embedded files found:");
        for blob in &embedded {
            println!(
                "    {} {:?} at offset {} ({})",
                "-".bright_black(),
                blob.file_type,
                format!("0x{:X}", blob.offset).bright_magenta().bold(),
                blob.signature
            );
        }

        if args.extract
            || ask_yes_no(&format!(
                "{}",
                "[?] Extract detected blobs?".yellow().bold()
            ))
        {
            if let Err(e) =
                extract_blobs(&args.file, &data, &embedded, &args.out, args.recursive, 0)
            {
                eprintln!("{} Extraction failed: {e}", "[-]".red().bold());
            }
        }
    }
}

// ── Banner ───────────────────────────────────────────────────────────────────
fn banner() {
    println!(
        "{}",
        r#"
  ███████╗████████╗███████╗ ██████╗  ██████╗ ██████╗ ██╗   ██╗███████╗████████╗██╗███╗   ██╗ ██████╗
  ██╔════╝╚══██╔══╝██╔════╝██╔════╝ ██╔═══██╗██╔══██╗██║   ██║██╔════╝╚══██╔══╝██║████╗  ██║██╔════╝
  ███████╗   ██║   █████╗  ██║  ███╗██║   ██║██████╔╝██║   ██║███████╗   ██║   ██║██╔██╗ ██║██║  ███╗
  ╚════██║   ██║   ██╔══╝  ██║   ██║██║   ██║██╔══██╗██║   ██║╚════██║   ██║   ██║██║╚██╗██║██║   ██║
  ███████║   ██║   ███████╗╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██║██║ ╚████║╚██████╔╝
  ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚═════╝
                         StegoRusting v0.2 — CTF / Forensics / Stego Scanner
"#
        .bright_blue()
        .bold()
    );
}

// ── UI helpers ───────────────────────────────────────────────────────────────
fn stage_header(stage: usize, title: &str) {
    println!(
        "\n{}",
        format!("========== STAGE {stage}: {title} ==========")
            .bright_cyan()
            .bold()
    );
}

fn print_ok(msg: &str) {
    println!("{} {}", "[+]".green().bold(), msg.green());
}

fn print_info(msg: &str) {
    println!("{} {}", "[*]".cyan().bold(), msg);
}

fn print_warn(msg: &str) {
    println!("{} {}", "[!]".yellow().bold(), msg.yellow());
}

// ── Default search vocabulary ────────────────────────────────────────────────
fn default_search_words() -> Vec<String> {
    // This covers most known CTF platforms and common hidden-data keywords.
    // Users can extend via --word / --wordlist.
    vec![
        // Generic flag formats
        "flag{".into(),
        "FLAG{".into(),
        "ctf{".into(),
        "CTF{".into(),
        "flag_it{".into(),
        "fl4g{".into(),
        // picoCTF
        "picoCTF{".into(),
        // Hack The Box
        "HTB{".into(),
        // TryHackMe
        "THM{".into(),
        "TRYHACKME{".into(),
        "tryhackme{".into(),
        // OverTheWire
        "OTW{".into(),
        // CTF365
        "CTF365{".into(),
        // Root-Me
        "rootme{".into(),
        "ROOTME{".into(),
        // Newbies / training
        "BrixelCTF{".into(),
        "MetaCTF{".into(),
        "shellctf{".into(),
        "RaziCTF{".into(),
        "SunshineCTF{".into(),
        "X-MAS{".into(),
        "DUCTF{".into(),
        "CSC{".into(),
        // Crackmes / reversing
        "flag{".into(),
        "password:".into(),
        "Password:".into(),
        "secret".into(),
        "SECRET".into(),
        "hidden".into(),
        "HIDDEN".into(),
        "magic".into(),
        "MAGIC".into(),
        "decrypt".into(),
        "encrypt".into(),
        "decode".into(),
        "cipher".into(),
        "CIPHER".into(),
        "key{".into(),
        "KEY{".into(),
        "token{".into(),
        "TOKEN{".into(),
        "base64".into(),
        "Base64".into(),
        "BASE64".into(),
        "Authorization:".into(),
        "Bearer ".into(),
        "sk-".into(), // OpenAI / API keys
        "AKIA".into(), // AWS access keys
    ]
}

fn read_wordlist(path: &Path) -> io::Result<Vec<String>> {
    let content = fs::read_to_string(path)?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(String::from)
        .collect())
}

// ── File-type detection ──────────────────────────────────────────────────────
fn detect_file_type(data: &[u8]) -> FileType {
    if data.starts_with(PNG_SIG) {
        FileType::Png
    } else if data.starts_with(JPG_SIG) {
        FileType::Jpeg
    } else if data.starts_with(GIF87_SIG) || data.starts_with(GIF89_SIG) {
        FileType::Gif
    } else if data.starts_with(ZIP_LOCAL_SIG)
        || data.starts_with(ZIP_EOCD_SIG)
        || data.starts_with(ZIP_SPANNED_SIG)
    {
        FileType::Zip
    } else if data.starts_with(RAR_SIG) {
        FileType::Rar
    } else if data.starts_with(PDF_SIG) {
        FileType::Pdf
    } else if data.starts_with(PE_SIG) {
        FileType::Pe
    } else if data.starts_with(ELF_SIG) {
        FileType::Elf
    } else if data.starts_with(SEVEN_ZIP_SIG) {
        FileType::SevenZip
    } else if data.starts_with(BZ2_SIG) {
        FileType::Bzip2
    } else if data.starts_with(GZIP_SIG) {
        FileType::Gzip
    } else if data.starts_with(XZ_SIG) {
        FileType::Xz
    } else if data.starts_with(LZ4_SIG) {
        FileType::Lz4
    } else if data.starts_with(CAB_SIG) {
        FileType::Cab
    } else if data.starts_with(ISO_SIG) {
        FileType::Iso
    } else if data.starts_with(DMG_SIG) {
        FileType::Dmg
    } else if data.starts_with(MACH_O_SIG_32)
        || data.starts_with(MACH_O_SIG_64)
        || data.starts_with(MACH_O_SIG_32_REV)
        || data.starts_with(MACH_O_SIG_64_REV)
    {
        FileType::MachO
    } else if data.starts_with(RIFF_SIG) {
        FileType::Riff
    } else {
        FileType::Unknown
    }
}

// ── Byte-pattern searching ──────────────────────────────────────────────────
fn search_literal(data: &[u8], pattern: &[u8], label: &str) -> Vec<Finding> {
    if pattern.is_empty() || data.len() < pattern.len() {
        return Vec::new();
    }

    data.windows(pattern.len())
        .enumerate()
        .filter_map(|(offset, window)| {
            if window == pattern {
                Some(Finding {
                    kind: "literal".into(),
                    label: label.into(),
                    offset,
                    preview: preview_ascii_around(data, offset, 96),
                })
            } else {
                None
            }
        })
        .collect()
}

fn search_regex(data: &[u8], re: &Regex, label: &str) -> Vec<Finding> {
    re.find_iter(data)
        .map(|m| Finding {
            kind: "regex".into(),
            label: label.into(),
            offset: m.start(),
            preview: preview_ascii_around(data, m.start(), 120),
        })
        .collect()
}

fn preview_ascii_around(data: &[u8], offset: usize, len: usize) -> String {
    let start = offset.saturating_sub(24);
    let end = usize::min(offset + len, data.len());
    data[start..end]
        .iter()
        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
        .collect()
}

fn print_findings(findings: &[Finding]) {
    if findings.is_empty() {
        print_info("No textual/hex patterns found.");
        return;
    }

    print_ok(&format!("Matches found: {}", findings.len()));
    for f in findings {
        println!(
            "\n    {} {}",
            format!("[{}]", f.kind).bright_blue().bold(),
            f.label.bold()
        );
        println!("    {} 0x{:X}", "Offset :".bright_black(), f.offset);
        println!("    {} {}", "Preview:".bright_black(), f.preview.bright_white());
    }
}

// ── Hex pattern parsing ──────────────────────────────────────────────────────
fn parse_hex_pattern(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != '-')
        .collect();

    if cleaned.len() % 2 != 0 {
        return Err("odd number of hex characters".into());
    }

    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

// ── Heuristic: find Base64-like strings ──────────────────────────────────────
fn find_base64_candidates(data: &[u8]) -> Vec<Finding> {
    let runs = extract_printable_runs(data, 28); // minimum 28 chars
    let mut out = Vec::new();

    for run in &runs {
        let compact: String = run.chars().filter(|c| !c.is_whitespace()).collect();
        if compact.len() < 16 || compact.len() % 4 != 0 {
            continue;
        }
        if !compact
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        {
            continue;
        }

        // Found a Base64 candidate — locate it roughly
        if let Some(offset) = find_bytes(data, compact.as_bytes()) {
            let preview = preview_ascii_around(data, offset, 80);
            let mut finding = Finding {
                kind: "base64-candidate".into(),
                label: format!("Base64 ({} chars)", compact.len()),
                offset,
                preview,
            };

            // Attempt to decode and show preview
            if let Some(decoded) = decode_base64_preview(&compact) {
                finding.label += &format!(" -> decoded: {}", &decoded[..std::cmp::min(decoded.len(), 80)]);
            }

            out.push(finding);
        }
    }

    out
}

// ── Heuristic: find long hex strings ─────────────────────────────────────────
fn find_hex_candidates(data: &[u8]) -> Vec<Finding> {
    let runs = extract_printable_runs(data, 32);
    let mut out = Vec::new();

    for run in &runs {
        let compact: String = run
            .chars()
            .filter(|c| !c.is_whitespace() && *c != ':' && *c != '-')
            .collect();
        if compact.len() < 24 || compact.len() % 2 != 0 {
            continue;
        }
        if !compact.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }

        if let Some(offset) = find_bytes(data, compact.as_bytes()) {
            out.push(Finding {
                kind: "hex-candidate".into(),
                label: format!("Hex ({} chars)", compact.len()),
                offset,
                preview: preview_ascii_around(data, offset, 80),
            });
        }
    }

    out
}

// ── Base64 decode helpers ────────────────────────────────────────────────────
fn decode_base64_preview(s: &str) -> Option<String> {
    let compact_raw: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if compact_raw.is_empty() {
        return None;
    }
    let padded = compact_raw.trim_end_matches('=').to_string()
        + &"=".repeat((4 - compact_raw.len() % 4) % 4);

    let decoded = general_purpose::STANDARD.decode(padded.as_bytes()).ok()?;
    if decoded.is_empty() {
        return None;
    }

    let printable_count = decoded
        .iter()
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .count();
    if printable_count * 100 / decoded.len() < 60 {
        return None; // mostly binary, skip
    }

    Some(
        decoded
            .iter()
            .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
            .take(200)
            .collect(),
    )
}

// ── Structural anomaly analysis ──────────────────────────────────────────────
fn analyze_format_anomalies(file_type: &FileType, data: &[u8]) {
    match file_type {
        FileType::Png => analyze_png(data),
        FileType::Jpeg => analyze_jpeg(data),
        FileType::Gif => analyze_gif(data),
        FileType::Zip => analyze_zip(data),
        FileType::Pdf => analyze_pdf(data),
        FileType::Pe => analyze_pe(data),
        FileType::Elf => analyze_elf(data),
        FileType::Gzip => analyze_gzip(data),
        FileType::Bzip2 => analyze_gzip(data), // same logic
        _ => print_info("No specific structural analyzer for this type."),
    }
}

fn analyze_png(data: &[u8]) {
    match find_bytes(data, b"IEND") {
        Some(pos) => {
            let expected_end = pos + 8;
            if data.len() > expected_end {
                print_warn(&format!(
                    "PNG has {} bytes after IEND chunk. Possible appended payload.",
                    data.len() - expected_end
                ));
            } else {
                print_ok("PNG appears to end correctly at IEND.");
            }
        }
        None => print_warn("No IEND chunk found. File may be altered/corrupted."),
    }
}

fn analyze_jpeg(data: &[u8]) {
    match find_last_bytes(data, JPG_EOI) {
        Some(pos) => {
            let expected_end = pos + 2;
            if data.len() > expected_end {
                print_warn(&format!(
                    "JPEG has {} bytes after EOI marker FFD9. Possible appended payload.",
                    data.len() - expected_end
                ));
            } else {
                print_ok("JPEG appears to end correctly at FFD9.");
            }
        }
        None => print_warn("No FFD9 end-of-image marker found. File may be altered/corrupted."),
    }
}

fn analyze_gif(data: &[u8]) {
    match data.iter().rposition(|&b| b == 0x3B) {
        Some(pos) => {
            if data.len() > pos + 1 {
                print_warn(&format!(
                    "GIF has {} bytes after trailer 0x3B. Possible appended payload.",
                    data.len() - pos - 1
                ));
            } else {
                print_ok("GIF appears to end correctly.");
            }
        }
        None => print_warn("No GIF trailer (0x3B) found."),
    }
}

fn analyze_zip(data: &[u8]) {
    if find_bytes(data, ZIP_EOCD_SIG).is_some() {
        print_ok("ZIP End of Central Directory record found.");
    } else {
        print_warn("No EOCD (PK 05 06) found. May be altered, truncated, or obfuscated.");
    }
}

fn analyze_pdf(data: &[u8]) {
    if let Some(pos) = find_last_bytes(data, b"%%EOF") {
        if data.len() > pos + 5 {
            print_warn(&format!(
                "PDF has data after %%EOF: {} bytes.",
                data.len() - (pos + 5)
            ));
        } else {
            print_ok("PDF %%EOF marker found at expected end.");
        }
    } else {
        print_warn("No %%EOF marker found in PDF.");
    }
}

fn analyze_pe(data: &[u8]) {
    if data.len() < 0x40 {
        print_warn("File too small for a valid DOS header.");
        return;
    }

    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if pe_offset + 4 <= data.len() && &data[pe_offset..pe_offset + 4] == PE_HEADER_SIG {
        print_ok(&format!("PE header found at 0x{:X}.", pe_offset));
    } else {
        print_warn("MZ signature present, but PE\\0\\0 not at expected offset. Possible tampering/obfuscation.");
    }
}

fn analyze_elf(data: &[u8]) {
    if data.len() >= 0x10 {
        let class = match data[4] {
            1 => "32-bit",
            2 => "64-bit",
            _ => "unknown class",
        };
        let endian = match data[5] {
            1 => "little-endian",
            2 => "big-endian",
            _ => "unknown endianness",
        };
        print_ok(&format!("ELF detected: {class}, {endian}."));
    }
}

fn analyze_gzip(data: &[u8]) {
    if data.len() >= 10 {
        let mtime = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if mtime == 0 {
            print_info("Gzip mtime is 0 (no timestamp). Common for stego/generated files.");
        } else {
            print_ok(&format!("Gzip mtime: {}", mtime));
        }
    }
}

// ── Metadata analysis ────────────────────────────────────────────────────────
fn analyze_metadata(file_type: &FileType, data: &[u8]) {
    match file_type {
        FileType::Jpeg => analyze_jpeg_metadata(data),
        FileType::Png => analyze_png_metadata(data),
        FileType::Gif => analyze_gif_metadata(data),
        FileType::Pdf => analyze_pdf_metadata(data),
        FileType::Zip => analyze_zip_metadata(data),
        _ => print_info("No simple metadata parser for this type."),
    }
}

fn analyze_jpeg_metadata(data: &[u8]) {
    if data.len() < 4 || !data.starts_with(&[0xFF, 0xD8]) {
        return;
    }

    let mut pos = 2;
    let mut found = false;

    while pos + 4 <= data.len() {
        if data[pos] != 0xFF {
            break;
        }

        let marker = data[pos + 1];
        if marker == 0xDA || marker == 0xD9 {
            break;
        }

        let seg_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        if seg_len < 2 || pos + 2 + seg_len > data.len() {
            print_warn(&format!("Inconsistent JPEG segment at 0x{:X}.", pos));
            break;
        }

        let payload = &data[pos + 4..pos + 2 + seg_len];

        match marker {
            0xE1 => {
                found = true;
                print_ok(&format!(
                    "JPEG APP1 / EXIF / XMP at 0x{:X}, {} bytes.",
                    pos,
                    payload.len()
                ));
                print_metadata_runs("JPEG-APP1", payload);
                inspect_suspicious_text("JPEG-APP1", payload);
            }
            0xFE => {
                found = true;
                print_ok(&format!("JPEG Comment at 0x{:X}:", pos));
                print_text_preview(payload, 180);
                print_metadata_runs("JPEG-COMMENT", payload);
                inspect_suspicious_text("JPEG-COMMENT", payload);
            }
            0xE0..=0xEF => {
                found = true;
                print_info(&format!(
                    "JPEG APP{} at 0x{:X}, {} bytes.",
                    marker - 0xE0,
                    pos,
                    payload.len()
                ));
                print_metadata_runs("JPEG-APP", payload);
                inspect_suspicious_text("JPEG-APP", payload);
            }
            _ => {}
        }

        pos += 2 + seg_len;
    }

    if !found {
        print_info("No relevant JPEG APP/Comment metadata found.");
    }
}

fn analyze_png_metadata(data: &[u8]) {
    if !data.starts_with(PNG_SIG) {
        return;
    }

    let mut pos = 8;
    let mut found = false;

    while pos + 12 <= data.len() {
        let len = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        if pos + 12 + len > data.len() {
            print_warn(&format!("Inconsistent PNG chunk at 0x{:X}.", pos));
            break;
        }

        let chunk_type = &data[pos + 4..pos + 8];
        let payload = &data[pos + 8..pos + 8 + len];
        let chunk_name = String::from_utf8_lossy(chunk_type);

        if matches!(chunk_type, b"tEXt" | b"iTXt" | b"zTXt" | b"eXIf") {
            found = true;
            print_ok(&format!("PNG chunk {} at 0x{:X}, {} bytes.", chunk_name, pos, len));
            print_text_preview(payload, 180);
            print_metadata_runs("PNG-METADATA", payload);
            inspect_suspicious_text("PNG-METADATA", payload);
        }

        if chunk_type == b"IEND" {
            break;
        }

        pos += 12 + len;
    }

    if !found {
        print_info("No relevant PNG textual/EXIF chunks found.");
    }
}

fn analyze_gif_metadata(data: &[u8]) {
    let comments = search_literal(data, &[0x21, 0xFE], "gif-comment-extension");
    if comments.is_empty() {
        print_info("No GIF comment blocks found.");
    } else {
        for c in comments {
            print_ok(&format!("Possible GIF comment at 0x{:X}", c.offset));
        }
        inspect_suspicious_text("GIF", data);
    }
}

fn analyze_pdf_metadata(data: &[u8]) {
    let keys: [&[u8]; 6] = [
        b"/Author",
        b"/Creator",
        b"/Producer",
        b"/Title",
        b"/Subject",
        b"/Keywords",
    ];

    for key in keys {
        for f in search_literal(data, key, &String::from_utf8_lossy(key)) {
            print_ok(&format!("PDF metadata {} at 0x{:X}: {}", f.label, f.offset, f.preview));
        }
    }
    inspect_suspicious_text("PDF", data);
}

fn analyze_zip_metadata(data: &[u8]) {
    if let Some(eocd) = find_last_bytes(data, ZIP_EOCD_SIG) {
        if eocd + 22 <= data.len() {
            let comment_len = u16::from_le_bytes([data[eocd + 20], data[eocd + 21]]) as usize;
            if comment_len > 0 && eocd + 22 + comment_len <= data.len() {
                let comment = &data[eocd + 22..eocd + 22 + comment_len];
                print_ok(&format!("ZIP comment found, {} bytes:", comment_len));
                print_text_preview(comment, 180);
                inspect_suspicious_text("ZIP-COMMENT", comment);
            } else {
                print_info("No ZIP comment in EOCD.");
            }
        }
    }
}

// ── Suspicious-text inspection (flags, tokens, base64, hex, secrets) ─────────
fn inspect_suspicious_text(context: &str, data: &[u8]) {
    for item in extract_printable_runs(data, 6) {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(reason) = classify_suspicious_text(trimmed) {
            println!("{} {}", "[!] Interesting find".yellow().bold(), format!("({context})").yellow());
            println!("    {} {}", "Reason  :".bright_black(), reason.yellow());
            println!("    {} {}", "Content :".bright_black(), trimmed.bright_white());

            if looks_like_base64(trimmed) {
                if let Some(decoded) = decode_base64_preview(trimmed) {
                    println!(
                        "    {} {}",
                        "B64 Dec :".bright_magenta().bold(),
                        decoded.bright_magenta()
                    );
                }
            }
        }
    }
}

fn classify_suspicious_text(s: &str) -> Option<&'static str> {
    let lower = s.to_lowercase();

    // Filter out common metadata noise
    let common_noise = lower.starts_with("http://ns.adobe.com")
        || lower.starts_with("http://www.w3.org")
        || lower.starts_with("http://creativecommons.org")
        || lower.contains("xpacket begin")
        || lower.contains("xpacket end")
        || lower.contains("rdf:rdf")
        || lower.contains("rdf:description")
        || lower.contains("xmlns:")
        || lower.contains("x:xmpmeta")
        || lower.starts_with("adobe")
        || lower.starts_with("dublin core");

    if common_noise {
        return None;
    }

    // Explicit flag patterns
    if lower.contains("flag{")
        || lower.contains("ctf{")
        || lower.contains("htb{")
        || lower.contains("thm{")
        || lower.contains("picoctf{")
        || lower.contains("ductf{")
        || lower.contains("sk-")
    {
        return Some("explicit flag/secret pattern");
    }

    // CTF platform names
    if lower.contains("picoctf")
        || lower.contains("hackthebox")
        || lower.contains("tryhackme")
    {
        return Some("CTF platform keyword in metadata");
    }

    // General CTF / flag keywords
    if lower.contains("flag")
        || lower.contains("ctf")
        || (lower.contains("secret") && !lower.contains("open secret"))
        || lower.contains("hidden")
        || lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("encrypt")
        || lower.contains("decrypt")
        || lower.contains("cipher")
        || lower.contains("base64")
    {
        return Some("sensitive/keyword in metadata");
    }

    // API keys / tokens
    if lower.starts_with("akia") || lower.starts_with("bearer ") {
        return Some("potential API key / token");
    }

    // Long Base64
    if looks_like_base64(s) {
        if let Some(decoded) = decode_base64_preview(s) {
            let dl = decoded.to_lowercase();
            if dl.contains("flag")
                || dl.contains("ctf")
                || dl.contains("pico")
                || dl.contains("secret")
                || dl.contains("password")
                || dl.contains("htb")
                || dl.contains("thm")
            {
                return Some("base64 decoded to relevant content");
            }
        }

        if s.len() >= 32 {
            return Some("long base64 string in metadata");
        }
    }

    // Long hex strings
    if looks_like_long_hex(s) && s.len() >= 48 {
        return Some("long hex string in metadata");
    }

    None
}

fn looks_like_base64(s: &str) -> bool {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    compact.len() >= 16
        && compact.len() % 4 == 0
        && compact
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

fn looks_like_long_hex(s: &str) -> bool {
    let compact: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != '-')
        .collect();
    compact.len() >= 24 && compact.len() % 2 == 0 && compact.chars().all(|c| c.is_ascii_hexdigit())
}

fn extract_printable_runs(data: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = Vec::new();

    for &b in data {
        if b.is_ascii_graphic() || b == b' ' {
            cur.push(b);
        } else {
            if cur.len() >= min_len {
                out.push(String::from_utf8_lossy(&cur).to_string());
            }
            cur.clear();
        }
    }

    if cur.len() >= min_len {
        out.push(String::from_utf8_lossy(&cur).to_string());
    }

    out
}

fn print_text_preview(data: &[u8], max_len: usize) {
    let preview = preview_ascii_around(data, 0, usize::min(data.len(), max_len));
    println!("    {} {}", "Preview:".bright_black(), preview.bright_white());
}

fn print_metadata_runs(context: &str, data: &[u8]) {
    let runs = extract_printable_runs(data, 6);
    if runs.is_empty() {
        return;
    }

    println!("{} {}", "[*] Readable fields in".cyan(), context.cyan().bold());

    let mut shown = 0;
    for item in runs.iter() {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }

        let lower = trimmed.to_lowercase();
        let common_noise = lower.starts_with("http://ns.adobe.com")
            || lower.starts_with("http://www.w3.org")
            || lower.starts_with("http://creativecommons.org")
            || lower.contains("xpacket begin")
            || lower.contains("xpacket end")
            || lower.contains("xmlns:");

        if common_noise {
            continue;
        }

        let relevant = lower.contains("license")
            || lower.contains("rights")
            || lower.contains("copyright")
            || lower.contains("comment")
            || lower.contains("description")
            || lower.contains("creator")
            || lower.contains("author")
            || lower.contains("pico")
            || lower.contains("flag")
            || lower.contains("ctf")
            || lower.contains("htb")
            || lower.contains("secret")
            || lower.contains("hidden")
            || lower.contains("password")
            || lower.contains("key")
            || lower.contains("token")
            || lower.contains("bearer")
            || looks_like_base64(trimmed)
            || looks_like_long_hex(trimmed);

        if relevant && shown < 80 {
            println!("    {} {}", "-".bright_black(), trimmed.bright_white());
            shown += 1;

            if looks_like_base64(trimmed) {
                if let Some(decoded) = decode_base64_preview(trimmed) {
                    println!(
                        "      {} {}",
                        "=> b64:".bright_magenta(),
                        decoded.bright_magenta()
                    );
                }
            }
        }
    }

    if runs.len() > 80 {
        println!(
            "    {} {} additional entries hidden (use --word / --regex for targeted search).",
            "...".bright_black(),
            runs.len() - 80
        );
    }
}

// ── Embedded file detection ──────────────────────────────────────────────────
fn find_embedded_files(data: &[u8]) -> Vec<EmbeddedBlob> {
    let signatures: Vec<(&[u8], FileType, &'static str)> = vec![
        (PNG_SIG, FileType::Png, "PNG"),
        (JPG_SIG, FileType::Jpeg, "JPEG"),
        (GIF87_SIG, FileType::Gif, "GIF87a"),
        (GIF89_SIG, FileType::Gif, "GIF89a"),
        (ZIP_LOCAL_SIG, FileType::Zip, "ZIP"),
        (RAR_SIG, FileType::Rar, "RAR"),
        (PDF_SIG, FileType::Pdf, "PDF"),
        (PE_SIG, FileType::Pe, "PE/MZ"),
        (ELF_SIG, FileType::Elf, "ELF"),
        (SEVEN_ZIP_SIG, FileType::SevenZip, "7z"),
        (BZ2_SIG, FileType::Bzip2, "BZ2"),
        (GZIP_SIG, FileType::Gzip, "GZIP"),
        (XZ_SIG, FileType::Xz, "XZ"),
        (CAB_SIG, FileType::Cab, "CAB"),
        (ISO_SIG, FileType::Iso, "ISO"),
        (MACH_O_SIG_32, FileType::MachO, "Mach-O 32"),
        (MACH_O_SIG_64, FileType::MachO, "Mach-O 64"),
        (MACH_O_SIG_32_REV, FileType::MachO, "Mach-O 32 rev"),
        (MACH_O_SIG_64_REV, FileType::MachO, "Mach-O 64 rev"),
        (RIFF_SIG, FileType::Riff, "RIFF"),
    ];

    let mut blobs = Vec::new();

    for (sig, kind, label) in signatures {
        let mut pos = 0;
        while pos < data.len() {
            if let Some(found) = find_bytes_from(data, sig, pos) {
                if found != 0 {
                    blobs.push(EmbeddedBlob {
                        file_type: kind.clone(),
                        offset: found,
                        signature: label,
                    });
                }
                pos = found + sig.len();
            } else {
                break;
            }
        }
    }

    blobs.sort_by_key(|b| b.offset);
    blobs.dedup_by_key(|b| b.offset);
    blobs
}

// ── Extraction ───────────────────────────────────────────────────────────────
fn extract_blobs(
    original: &Path,
    data: &[u8],
    blobs: &[EmbeddedBlob],
    out_dir: &Path,
    recursive: bool,
    depth: usize,
) -> io::Result<()> {
    fs::create_dir_all(out_dir)?;

    for (idx, blob) in blobs.iter().enumerate() {
        let end = calculate_blob_end(data, blob, blobs.get(idx + 1).map(|next| next.offset));

        if blob.offset >= end || end > data.len() {
            continue;
        }

        let ext = extension_for_type(&blob.file_type);
        let base = original
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("sample");

        let output = out_dir.join(format!(
            "{}_blob_{:03}_0x{:X}.{}",
            base,
            idx + 1,
            blob.offset,
            ext
        ));
        let extracted = &data[blob.offset..end];
        fs::write(&output, extracted)?;
        print_ok(&format!("Extracted: {}", output.display()));

        if recursive && depth < 3 {
            let nested = find_embedded_files(extracted);
            if !nested.is_empty() {
                print_warn(&format!(
                    "Additional blobs found inside {}",
                    output.display()
                ));
                let nested_out =
                    out_dir.join(format!("nested_{:03}_0x{:X}", idx + 1, blob.offset));
                extract_blobs(
                    &output,
                    extracted,
                    &nested,
                    &nested_out,
                    recursive,
                    depth + 1,
                )?;
            }
        }
    }

    Ok(())
}

fn calculate_blob_end(
    data: &[u8],
    blob: &EmbeddedBlob,
    next_magic_offset: Option<usize>,
) -> usize {
    match blob.file_type {
        FileType::Zip => zip_end_offset(data, blob.offset)
            .unwrap_or_else(|| next_magic_offset.unwrap_or(data.len())),
        FileType::Png => png_end_offset(data, blob.offset)
            .unwrap_or_else(|| next_magic_offset.unwrap_or(data.len())),
        FileType::Jpeg => jpeg_end_offset(data, blob.offset)
            .unwrap_or_else(|| next_magic_offset.unwrap_or(data.len())),
        FileType::Gif => gif_end_offset(data, blob.offset)
            .unwrap_or_else(|| next_magic_offset.unwrap_or(data.len())),
        FileType::Pdf => pdf_end_offset(data, blob.offset)
            .unwrap_or_else(|| next_magic_offset.unwrap_or(data.len())),
        _ => next_magic_offset.unwrap_or(data.len()),
    }
}

fn zip_end_offset(data: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    let mut last_eocd = None;

    while let Some(found) = find_bytes_from(data, ZIP_EOCD_SIG, pos) {
        last_eocd = Some(found);
        pos = found + ZIP_EOCD_SIG.len();
    }

    let eocd = last_eocd?;
    if eocd + 22 > data.len() {
        return None;
    }

    let comment_len = u16::from_le_bytes([data[eocd + 20], data[eocd + 21]]) as usize;
    let end = eocd + 22 + comment_len;

    if end <= data.len() {
        Some(end)
    } else {
        None
    }
}

fn png_end_offset(data: &[u8], start: usize) -> Option<usize> {
    find_bytes_from(data, b"IEND", start).map(|pos| pos + 8)
}

fn jpeg_end_offset(data: &[u8], start: usize) -> Option<usize> {
    find_bytes_from(data, JPG_EOI, start).map(|pos| pos + 2)
}

fn gif_end_offset(data: &[u8], start: usize) -> Option<usize> {
    data[start..]
        .iter()
        .position(|&b| b == 0x3B)
        .map(|pos| start + pos + 1)
}

fn pdf_end_offset(data: &[u8], start: usize) -> Option<usize> {
    find_bytes_from(data, b"%%EOF", start).map(|pos| pos + 5)
}

fn extension_for_type(t: &FileType) -> &'static str {
    match t {
        FileType::Png => "png",
        FileType::Jpeg => "jpg",
        FileType::Gif => "gif",
        FileType::Zip => "zip",
        FileType::Rar => "rar",
        FileType::Pdf => "pdf",
        FileType::Pe => "exe",
        FileType::Elf => "elf",
        FileType::SevenZip => "7z",
        FileType::Bzip2 => "bz2",
        FileType::Gzip => "gz",
        FileType::Xz => "xz",
        FileType::Lz4 => "lz4",
        FileType::Cab => "cab",
        FileType::Iso => "iso",
        FileType::Dmg => "dmg",
        FileType::MachO => "macho",
        FileType::Riff => "wav",
        FileType::WebP => "webp",
        FileType::Unknown => "bin",
    }
}

// ── Helper: ask yes/no ───────────────────────────────────────────────────────
fn ask_yes_no(question: &str) -> bool {
    print!("{question} [y/N]: ");
    let _ = io::stdout().flush();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_ok() {
        matches!(input.trim().to_lowercase().as_str(), "y" | "yes" | "s" | "sim")
    } else {
        false
    }
}

// ── Byte-search utilities ────────────────────────────────────────────────────
fn find_bytes(data: &[u8], needle: &[u8]) -> Option<usize> {
    find_bytes_from(data, needle, 0)
}

fn find_bytes_from(data: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || start >= data.len() || data.len() < needle.len() {
        return None;
    }

    data[start..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|pos| pos + start)
}

fn find_last_bytes(data: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || data.len() < needle.len() {
        return None;
    }

    data.windows(needle.len()).rposition(|window| window == needle)
}
