use thiserror::Error;

use crate::{
    config::DatabaseVersion,
    db::Database,
    format::{
        kdb::parse_kdb,
        kdbx3::{decrypt_kdbx3, parse_kdbx3, parse_kdbx3_with_limits},
        kdbx4::{decrypt_kdbx4, parse_kdbx4, parse_kdbx4_with_limits},
        DatabaseVersionParseError,
    },
    DatabaseKey,
};

/// Resource limits applied while opening a database through the bounded APIs.
///
/// The existing [`Database::open`] and [`Database::parse`] methods retain their historical
/// behavior. Callers processing untrusted KDBX files should prefer [`Database::open_with_limits`]
/// or [`Database::parse_with_limits`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatabaseOpenLimits {
    /// Maximum number of bytes read from an input stream by [`Database::open_with_limits`].
    pub max_input_bytes: usize,
    /// Maximum number of bytes produced by decompression of the KDBX payload.
    pub max_decompressed_payload_bytes: usize,
    /// Maximum size of a single binary attachment after decoding/decompression.
    pub max_decompressed_binary_bytes: usize,
    /// Maximum aggregate size of binary attachments after decoding/decompression.
    pub max_total_decompressed_binary_bytes: usize,
}

impl DatabaseOpenLimits {
    /// Limits that preserve the historical effectively-unbounded behavior.
    pub const UNLIMITED: Self = Self {
        max_input_bytes: usize::MAX,
        max_decompressed_payload_bytes: usize::MAX,
        max_decompressed_binary_bytes: usize::MAX,
        max_total_decompressed_binary_bytes: usize::MAX,
    };
}

impl Default for DatabaseOpenLimits {
    fn default() -> Self {
        Self::UNLIMITED
    }
}

/// Resource-limit failures raised by the bounded database-opening APIs.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DatabaseResourceLimitError {
    #[error("database input exceeds configured limit of {limit} bytes")]
    InputBytes { limit: usize },

    #[error("decompressed database payload exceeds configured limit of {limit} bytes")]
    DecompressedPayloadBytes { limit: usize },

    #[error("decompressed binary exceeds configured limit of {limit} bytes")]
    DecompressedBinaryBytes { limit: usize },

    #[error("total decompressed binary data exceeds configured limit of {limit} bytes")]
    TotalDecompressedBinaryBytes { limit: usize },
}

impl Database {
    /// Parse a database from a std::io::Read.
    pub fn open(source: &mut dyn std::io::Read, key: DatabaseKey) -> Result<Database, DatabaseOpenError> {
        let mut data = Vec::new();
        source.read_to_end(&mut data)?;

        Database::parse(data.as_ref(), key)
    }

    /// Parse a database from a std::io::Read while enforcing resource limits.
    pub fn open_with_limits(
        source: &mut dyn std::io::Read,
        key: DatabaseKey,
        limits: DatabaseOpenLimits,
    ) -> Result<Database, DatabaseOpenError> {
        let read_limit = u64::try_from(limits.max_input_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let mut limited = source.take(read_limit);
        let mut data = Vec::new();
        limited.read_to_end(&mut data)?;

        if data.len() > limits.max_input_bytes {
            return Err(DatabaseResourceLimitError::InputBytes {
                limit: limits.max_input_bytes,
            }
            .into());
        }

        Database::parse_with_limits(data.as_ref(), key, limits)
    }

    /// Parse a database from a byte slice.
    pub fn parse(data: &[u8], key: DatabaseKey) -> Result<Database, DatabaseOpenError> {
        let database_version = DatabaseVersion::parse(data)?;

        match database_version {
            DatabaseVersion::KDB(_) => parse_kdb(data, &key),
            DatabaseVersion::KDB2(_) => Err(DatabaseOpenError::UnsupportedVersion),
            DatabaseVersion::KDB3(_) => parse_kdbx3(data, &key),
            DatabaseVersion::KDB4(_) => parse_kdbx4(data, &key),
        }
    }

    /// Parse a database from a byte slice while enforcing resource limits.
    pub fn parse_with_limits(
        data: &[u8],
        key: DatabaseKey,
        limits: DatabaseOpenLimits,
    ) -> Result<Database, DatabaseOpenError> {
        if data.len() > limits.max_input_bytes {
            return Err(DatabaseResourceLimitError::InputBytes {
                limit: limits.max_input_bytes,
            }
            .into());
        }

        let database_version = DatabaseVersion::parse(data)?;

        match database_version {
            DatabaseVersion::KDB(_) => parse_kdb(data, &key),
            DatabaseVersion::KDB2(_) => Err(DatabaseOpenError::UnsupportedVersion),
            DatabaseVersion::KDB3(_) => parse_kdbx3_with_limits(data, &key, limits),
            DatabaseVersion::KDB4(_) => parse_kdbx4_with_limits(data, &key, limits),
        }
    }

    /// Helper function to load a database into its internal XML chunks.
    pub fn get_xml(source: &mut dyn std::io::Read, key: DatabaseKey) -> Result<Vec<u8>, DatabaseOpenError> {
        let mut data = Vec::new();
        source.read_to_end(&mut data)?;

        let database_version = DatabaseVersion::parse(data.as_ref())?;

        let data = match database_version {
            DatabaseVersion::KDB(_) => return Err(DatabaseOpenError::UnsupportedVersion),
            DatabaseVersion::KDB2(_) => return Err(DatabaseOpenError::UnsupportedVersion),
            DatabaseVersion::KDB3(_) => decrypt_kdbx3(data.as_ref(), &key)?.2,
            DatabaseVersion::KDB4(_) => decrypt_kdbx4(data.as_ref(), &key)?.3,
        };

        Ok(data)
    }

    /// Get the version of a database without decrypting it.
    pub fn get_version(source: &mut dyn std::io::Read) -> Result<DatabaseVersion, DatabaseOpenError> {
        let mut data = vec![0; DatabaseVersion::get_version_header_size()];
        source.read_exact(&mut data)?;
        let version = DatabaseVersion::parse(data.as_ref())?;
        Ok(version)
    }
}

/// Errors that can occur when opening a database.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DatabaseOpenError {
    /// I/O errors that can occur while reading the database from the source.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Resource limits configured by a bounded open/parse API were exceeded.
    #[error(transparent)]
    ResourceLimit(#[from] DatabaseResourceLimitError),

    /// An unexpected end of file was encountered while reading the database.
    #[error("Unexpected end of file")]
    UnexpectedEof,

    /// Errors related to parsing the database version from the file header.
    #[error(transparent)]
    VersionParse(#[from] DatabaseVersionParseError),

    /// Attempted to open a database with an unsupported version.
    #[error("Unsupported database version")]
    UnsupportedVersion,

    /// Errors related to the database key, such as incorrect keys.
    #[error(transparent)]
    Key(#[from] crate::key::DatabaseKeyError),

    /// Errors related to decryption.
    #[error(transparent)]
    Cryptography(#[from] crate::crypt::CryptographyError),

    /// Errors related to parsing the database format.
    #[error(transparent)]
    Format(#[from] DatabaseFormatError),
}

/// Format-specific database parsing errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DatabaseFormatError {
    /// Errors related to parsing KDB files.
    #[error(transparent)]
    Kdb(#[from] crate::format::kdb::KdbOpenError),

    /// Errors related to parsing KDBX3 files.
    #[error(transparent)]
    Kdbx3(#[from] crate::format::kdbx3::Kdbx3OpenError),

    /// Errors related to parsing KDBX4 files.
    #[error(transparent)]
    Kdbx4(#[from] crate::format::kdbx4::Kdbx4OpenError),
}
