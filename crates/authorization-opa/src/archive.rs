//! The archive of a bundle, a gzip-compressed tar file, and reading the
//! gzip-compressed reports of an instance.
//!
//! Written by hand on a deflate library: a bundle holds a few regular
//! files, and the tar format needs nothing more than their headers.

use hodor_kernel::DomainError;

const BLOCK: usize = 512;
const NAME: usize = 100;
const PREFIX: usize = 155;

fn archive_error(message: &'static str) -> DomainError {
    DomainError::invalid("authorization.bundle_archive_invalid", message)
}

/// Writes `value` as an octal number of `width - 1` digits and a zero byte.
fn octal(field: &mut [u8], value: u64) -> Result<(), DomainError> {
    let digits = field.len() - 1;
    let text = format!("{value:0digits$o}");
    if text.len() > digits {
        return Err(archive_error("a file of the bundle is too large"));
    }
    field[..digits].copy_from_slice(text.as_bytes());
    field[digits] = 0;
    Ok(())
}

/// Splits a path into the `prefix` and `name` fields of a ustar header.
fn split_path(path: &str) -> Result<(&str, &str), DomainError> {
    if path.len() <= NAME {
        return Ok(("", path));
    }
    for (index, character) in path.char_indices() {
        if character == '/' {
            let (prefix, name) = (&path[..index], &path[index + 1..]);
            if prefix.len() <= PREFIX && !name.is_empty() && name.len() <= NAME {
                return Ok((prefix, name));
            }
        }
    }
    Err(archive_error("a path of the bundle is too long"))
}

fn header(path: &str, size: usize) -> Result<[u8; BLOCK], DomainError> {
    let (prefix, name) = split_path(path)?;
    let mut block = [0_u8; BLOCK];
    block[..name.len()].copy_from_slice(name.as_bytes());
    octal(&mut block[100..108], 0o644)?;
    octal(&mut block[108..116], 0)?;
    octal(&mut block[116..124], 0)?;
    octal(
        &mut block[124..136],
        u64::try_from(size).map_err(|_| archive_error("a file of the bundle is too large"))?,
    )?;
    // The time of every file is zero, so that the same files make the
    // same archive.
    octal(&mut block[136..148], 0)?;
    block[156] = b'0';
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    block[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    // The checksum is computed with its own field as spaces.
    block[148..156].copy_from_slice(b"        ");
    let sum: u64 = block.iter().map(|byte| u64::from(*byte)).sum();
    let text = format!("{sum:06o}");
    block[148..154].copy_from_slice(text.as_bytes());
    block[154] = 0;
    block[155] = b' ';
    Ok(block)
}

/// A tar file of `files`, in the order given.
///
/// # Errors
///
/// Returns `authorization.bundle_archive_invalid` for a path the format
/// cannot hold.
pub(crate) fn tar(files: &[(String, Vec<u8>)]) -> Result<Vec<u8>, DomainError> {
    let mut out = Vec::new();
    for (path, contents) in files {
        out.extend_from_slice(&header(path, contents.len())?);
        out.extend_from_slice(contents);
        let padding = (BLOCK - contents.len() % BLOCK) % BLOCK;
        out.resize(out.len() + padding, 0);
    }
    out.resize(out.len() + 2 * BLOCK, 0);
    Ok(out)
}

/// The CRC-32 of gzip (the polynomial of IEEE 802.3, reflected).
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// `data` compressed in the gzip format, with no name and no time.
#[must_use]
pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    out.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(data, 6));
    out.extend_from_slice(&crc32(data).to_le_bytes());
    // The length modulo 2^32, as the format says.
    #[allow(clippy::cast_possible_truncation)]
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

fn report_error(message: &'static str) -> DomainError {
    DomainError::invalid("authorization.policy_agent_report_invalid", message)
}

/// The contents of one gzip member, refused if expanded they are longer
/// than `limit` bytes.
///
/// # Errors
///
/// Returns `authorization.policy_agent_report_invalid` for data that is
/// not gzip, is damaged, or expands beyond `limit`.
pub(crate) fn gunzip(data: &[u8], limit: usize) -> Result<Vec<u8>, DomainError> {
    const TEXT: u8 = 1;
    const HEADER_CRC: u8 = 2;
    const EXTRA: u8 = 4;
    const NAME: u8 = 8;
    const COMMENT: u8 = 16;
    if data.len() < 18 || data[0] != 0x1f || data[1] != 0x8b || data[2] != 8 {
        return Err(report_error("the report is not gzip-compressed"));
    }
    let flags = data[3];
    if flags & !(TEXT | HEADER_CRC | EXTRA | NAME | COMMENT) != 0 {
        return Err(report_error("the report is not gzip-compressed"));
    }
    let mut position = 10;
    if flags & EXTRA != 0 {
        let length = data
            .get(position..position + 2)
            .map(|bytes| usize::from(u16::from_le_bytes([bytes[0], bytes[1]])))
            .ok_or_else(|| report_error("the report is damaged"))?;
        position += 2 + length;
    }
    for flag in [NAME, COMMENT] {
        if flags & flag != 0 {
            let end = data
                .get(position..)
                .and_then(|rest| rest.iter().position(|byte| *byte == 0))
                .ok_or_else(|| report_error("the report is damaged"))?;
            position += end + 1;
        }
    }
    if flags & HEADER_CRC != 0 {
        position += 2;
    }
    if position + 8 > data.len() {
        return Err(report_error("the report is damaged"));
    }
    let (body, trailer) = data[position..].split_at(data.len() - position - 8);
    let contents = miniz_oxide::inflate::decompress_to_vec_with_limit(body, limit)
        .map_err(|_| report_error("the report is damaged or expands beyond the limit"))?;
    let crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let length = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
    #[allow(clippy::cast_possible_truncation)]
    if crc != crc32(&contents) || length != contents.len() as u32 {
        return Err(report_error("the report is damaged"));
    }
    Ok(contents)
}

/// The regular files of a tar file, for tests.
#[cfg(any(test, feature = "testing"))]
#[must_use]
pub(crate) fn untar(data: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    let mut position = 0;
    while position + BLOCK <= data.len() {
        let block = &data[position..position + BLOCK];
        if block.iter().all(|byte| *byte == 0) {
            break;
        }
        let field = |range: std::ops::Range<usize>| {
            let bytes = &block[range];
            let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
            String::from_utf8(bytes[..end].to_vec()).expect("text")
        };
        let name = field(0..100);
        let prefix = field(345..500);
        let size = usize::from_str_radix(field(124..135).trim(), 8).expect("size");
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let start = position + BLOCK;
        files.push((path, data[start..start + size].to_vec()));
        position = start + size.div_ceil(BLOCK) * BLOCK;
    }
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tar_file_holds_its_files_with_long_paths() {
        let long = format!(
            "hodor/tenants/t{}/resource_servers/r{}/policy.rego",
            "a".repeat(32),
            "b".repeat(32)
        );
        let files = vec![
            (".manifest".to_owned(), b"{}".to_vec()),
            (long, vec![b'x'; 1000]),
        ];
        let archive = tar(&files).expect("tar");
        assert_eq!(archive.len() % BLOCK, 0);
        assert_eq!(untar(&archive), files);
    }

    #[test]
    fn a_path_too_long_for_the_format_is_refused() {
        let path = "a".repeat(101);
        assert!(tar(&[(path, Vec::new())]).is_err());
    }

    #[test]
    fn the_crc_is_that_of_gzip() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn gzip_reads_back_and_is_bounded() {
        let data = b"[{\"decision_id\":\"1\"}]".repeat(100);
        let compressed = gzip(&data);
        assert_eq!(gunzip(&compressed, data.len()).expect("gunzip"), data);
        assert!(gunzip(&compressed, data.len() - 1).is_err());
        let mut damaged = compressed.clone();
        let last = damaged.len() - 5;
        damaged[last] ^= 1;
        assert!(gunzip(&damaged, data.len()).is_err());
        assert!(gunzip(b"not gzip at all, really", 1000).is_err());
    }
}
