use std::fs::File;

use osv_store::SyncWriter;

use crate::incremental::SyncError;

pub(crate) fn load(writer: &mut SyncWriter, file: File) -> Result<(), SyncError> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(file);
    let mut records = reader.records().enumerate();
    let mut count = 0;
    let rows = std::iter::from_fn(|| {
        let (index, row) = records.next()?;
        Some((|| {
            let row = row?;
            if index as u64 >= crate::MAX_ENTRIES * 4 || row.len() != 2 {
                return Err(SyncError::InventoryRow {
                    row: index + 1,
                    message: "expected a timestamp and ecosystem/ID within inventory limits".into(),
                });
            }
            let key =
                osv_schema::timestamp_key(&row[0]).map_err(|error| SyncError::InventoryRow {
                    row: index + 1,
                    message: error.to_string(),
                })?;
            let (ecosystem, id) = row[1]
                .split_once('/')
                .filter(|(ecosystem, id)| {
                    ecosystem.len() <= 512
                        && id.len() <= 512
                        && osv_schema::is_indexable_id(ecosystem)
                        && osv_schema::is_indexable_id(id)
                })
                .ok_or_else(|| SyncError::InventoryRow {
                    row: index + 1,
                    message: format!("invalid export path {:?}", &row[1]),
                })?;
            count += 1;
            Ok((id.into(), ecosystem.into(), key))
        })())
    });
    writer.load_inventory(rows)?;
    if count == 0 {
        return Err(SyncError::InvalidInventory("inventory is empty"));
    }
    Ok(())
}

/// The export contains one record per physical line, including quoted paths.
/// Reject multiline fields before the CSV parser can buffer them.
#[derive(Default)]
pub(crate) struct Framing {
    line_bytes: usize,
    quoted: bool,
}

impl Framing {
    pub(crate) fn check_chunk(&mut self, chunk: &[u8]) -> Result<(), SyncError> {
        const MAX_LINE: usize = 16 * 1024;
        for line in chunk.split_inclusive(|byte| *byte == b'\n') {
            self.line_bytes += line.len();
            if self.line_bytes > MAX_LINE {
                return Err(SyncError::InvalidInventory("inventory line exceeds 16 KiB"));
            }
            self.quoted ^= line.iter().filter(|&&byte| byte == b'"').count() % 2 != 0;
            if line.ends_with(b"\n") {
                if self.quoted {
                    return Err(SyncError::InvalidInventory("unterminated CSV quote"));
                }
                self.line_bytes = 0;
            }
        }
        Ok(())
    }

    pub(crate) fn at_line_end(&self) -> bool {
        self.line_bytes == 0
    }
}
