use thiserror::Error;

use crate::{config::DatabaseVersion, db::Database, DatabaseKey};

impl Database {
    /// Saves the database to the given destination, using the provided key for encryption.
    pub fn save(
        &self,
        destination: &mut dyn std::io::Write,
        key: DatabaseKey,
    ) -> Result<(), DatabaseSaveError> {
        use crate::format::kdbx4::dump_kdbx4;

        if !self.ignored_xml_paths.is_empty() {
            return Err(DatabaseSaveError::UnpreservedXmlFields {
                count: self.ignored_xml_paths.len(),
            });
        }

        match self.config.version {
            DatabaseVersion::KDB(_) => Err(DatabaseSaveError::UnsupportedVersion),
            DatabaseVersion::KDB2(_) => Err(DatabaseSaveError::UnsupportedVersion),
            DatabaseVersion::KDB3(_) => Err(DatabaseSaveError::UnsupportedVersion),
            DatabaseVersion::KDB4(_) => dump_kdbx4(self, &key, destination),
        }
    }
}

/// Errors that can occur during saving of the database to a KDBX file
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DatabaseSaveError {
    /// I/O errors that can occur while writing the database to the destination, such as file system errors
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Errors related to XML serialization of the database
    #[error(transparent)]
    Serialization(#[from] quick_xml::SeError),

    /// Errors related to database key operations
    #[error(transparent)]
    Key(#[from] crate::key::DatabaseKeyError),

    /// Errors related to encryption operations
    #[error(transparent)]
    Cryptography(#[from] crate::crypt::CryptographyError),

    /// Errors related to random number generation
    #[error(transparent)]
    Random(#[from] getrandom::Error),

    /// Attempted to save a database with XML fields that were ignored while reading and cannot
    /// therefore be preserved safely by this serializer.
    #[error("Database contains {count} unpreserved XML field(s)")]
    UnpreservedXmlFields {
        /// Number of ignored XML paths reported by the tolerant parser.
        count: usize,
    },

    /// Attempted to save a database with an unsupported version (e.g., KDB, KDBX2, or KDBX3)
    #[error("Unsupported database version")]
    UnsupportedVersion,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_rejects_ignored_xml_fields_before_writing_output() {
        let mut database = Database::new();
        database.config.version = DatabaseVersion::KDB4(1);
        database
            .ignored_xml_paths
            .push("Root.Entry.FortressUnknown".to_string());

        let mut output = Vec::new();
        let error = database
            .save(
                &mut output,
                DatabaseKey::new().with_password("synthetic-test-password"),
            )
            .expect_err("ignored source XML must block potentially lossy serialization");

        assert!(matches!(
            error,
            DatabaseSaveError::UnpreservedXmlFields { count: 1 }
        ));
        assert!(output.is_empty());
    }
}
