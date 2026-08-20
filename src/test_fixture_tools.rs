//! Test-only helpers for generating deliberately malformed, authenticated KDBX fixtures.
//!
//! This module is available only with the `test_fixture_tools` feature and is not
//! intended for production password-manager code.

use std::io::Write;

use crate::{
    db::{Database, DatabaseSaveError},
    DatabaseKey,
};

/// Writes a KDBX 4.1 container using `db` for its cryptographic configuration
/// while replacing the serialized XML document with `raw_xml`.
///
/// The resulting file still has a valid KDBX outer header, encryption and HMAC,
/// which lets downstream parser tests reach post-decrypt XML error paths. Binary
/// attachments are intentionally omitted because malformed-XML fixtures do not
/// need them.
pub fn dump_kdbx4_with_raw_xml(
    db: &Database,
    db_key: &DatabaseKey,
    raw_xml: &[u8],
    writer: &mut dyn Write,
) -> Result<(), DatabaseSaveError> {
    crate::format::kdbx4::dump_kdbx4_with_raw_xml(db, db_key, raw_xml, writer)
}
