use crate::{
    config::{CompressionConfig, DatabaseConfig, InnerCipherConfig, KdfConfig, OuterCipherConfig},
    crypt::{calculate_sha256, ciphers::Cipher},
    compression::DecompressionError,
    db::{Database, DatabaseFormatError, DatabaseOpenError, DatabaseOpenLimits, DatabaseResourceLimitError},
    format::DatabaseVersion,
    key::{DatabaseKey, DatabaseKeyError},
};

use byteorder::{ByteOrder, LittleEndian};
use thiserror::Error;

use std::convert::TryFrom;

#[derive(Debug)]
struct KDBX3Header {
    // https://gist.github.com/msmuenchen/9318327
    outer_cipher: OuterCipherConfig,
    compression: CompressionConfig,
    master_seed: Vec<u8>,

    transform_seed: Vec<u8>,
    kdf_config: KdfConfig,

    outer_iv: Vec<u8>,
    protected_stream_key: Vec<u8>,
    stream_start: Vec<u8>,
    inner_cipher: InnerCipherConfig,
    body_start: usize,
}

fn parse_outer_header(data: &[u8]) -> Result<KDBX3Header, Kdbx3OuterHeaderError> {
    let mut outer_cipher: Option<OuterCipherConfig> = None;
    let mut compression: Option<CompressionConfig> = None;
    let mut master_seed: Option<Vec<u8>> = None;
    let mut transform_seed: Option<Vec<u8>> = None;
    let mut transform_rounds: Option<u64> = None;
    let mut outer_iv: Option<Vec<u8>> = None;
    let mut protected_stream_key: Option<Vec<u8>> = None;
    let mut stream_start: Option<Vec<u8>> = None;
    let mut inner_cipher: Option<InnerCipherConfig> = None;

    // skip over the version header
    let mut pos = DatabaseVersion::get_version_header_size();

    // parse header
    loop {
        // parse header blocks.
        //
        // every block is a triplet of (3 + entry_length) bytes with this structure:
        //
        // (
        //   entry_type: u8,                        // a numeric entry type identifier
        //   entry_length: u16,                     // length of the entry buffer
        //   entry_buffer: [u8; entry_length]       // the entry buffer
        // )

        let entry_type = *data.get(pos).ok_or(Kdbx3OuterHeaderError::UnexpectedEof)?;

        let entry_length = data
            .get((pos + 1)..(pos + 3))
            .ok_or(Kdbx3OuterHeaderError::UnexpectedEof)?;
        let entry_length: usize = LittleEndian::read_u16(entry_length) as usize;

        let entry_buffer = data
            .get((pos + 3)..(pos + 3 + entry_length))
            .ok_or(Kdbx3OuterHeaderError::UnexpectedEof)?;

        pos += 3 + entry_length;

        match entry_type {
            0 => break,
            1 => {}
            2 => outer_cipher = Some(OuterCipherConfig::try_from(entry_buffer)?),
            3 => compression = Some(CompressionConfig::try_from(LittleEndian::read_u32(entry_buffer))?),
            4 => master_seed = Some(entry_buffer.to_vec()),
            5 => transform_seed = Some(entry_buffer.to_vec()),
            6 => transform_rounds = Some(LittleEndian::read_u64(entry_buffer)),
            7 => outer_iv = Some(entry_buffer.to_vec()),
            8 => protected_stream_key = Some(entry_buffer.to_vec()),
            9 => stream_start = Some(entry_buffer.to_vec()),
            10 => inner_cipher = Some(InnerCipherConfig::try_from(LittleEndian::read_u32(entry_buffer))?),
            _ => return Err(Kdbx3OuterHeaderError::InvalidOuterHeaderEntry(entry_type)),
        };
    }

    fn get_or_err<T>(v: Option<T>, err: &'static str) -> Result<T, Kdbx3OuterHeaderError> {
        v.ok_or(Kdbx3OuterHeaderError::IncompleteOuterHeader(err))
    }

    let outer_cipher = get_or_err(outer_cipher, "Outer Cipher ID")?;
    let compression = get_or_err(compression, "Compression ID")?;
    let master_seed = get_or_err(master_seed, "Master seed")?;
    let transform_seed = get_or_err(transform_seed, "Transform seed")?;
    let transform_rounds = get_or_err(transform_rounds, "Number of transformation rounds")?;
    let outer_iv = get_or_err(outer_iv, "Outer cipher IV")?;
    let protected_stream_key = get_or_err(protected_stream_key, "Protected stream key")?;
    let stream_start = get_or_err(stream_start, "Stream start bytes")?;
    let inner_cipher = get_or_err(inner_cipher, "Inner cipher ID")?;

    let kdf_config = KdfConfig::Aes { rounds: transform_rounds };

    Ok(KDBX3Header {
        outer_cipher,
        compression,
        master_seed,
        transform_seed,
        kdf_config,
        outer_iv,
        protected_stream_key,
        stream_start,
        inner_cipher,
        body_start: pos,
    })
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Kdbx3OuterHeaderError {
    #[error(transparent)]
    InnerCipher(#[from] crate::config::InnerCipherConfigError),
    #[error(transparent)]
    OuterCipher(#[from] crate::config::OuterCipherConfigError),
    #[error(transparent)]
    Compression(#[from] crate::config::CompressionConfigError),
    #[error("Encountered invalid outer header entry with type {0}")]
    InvalidOuterHeaderEntry(u8),
    #[error("Outer header is missing {0}")]
    IncompleteOuterHeader(&'static str),
    #[error("Unexpected end of file while reading outer header")]
    UnexpectedEof,
}

pub(crate) fn parse_kdbx3(data: &[u8], db_key: &DatabaseKey) -> Result<Database, DatabaseOpenError> {
    parse_kdbx3_with_limits(data, db_key, DatabaseOpenLimits::default())
}

pub(crate) fn parse_kdbx3_with_limits(
    data: &[u8],
    db_key: &DatabaseKey,
    limits: DatabaseOpenLimits,
) -> Result<Database, DatabaseOpenError> {
    let (config, mut inner_decryptor, xml) = decrypt_kdbx3_with_limits(data, db_key, limits)?;

    let mut db = match crate::format::xml_db::parse_xml_with_limits(
        &xml,
        &[],
        &mut *inner_decryptor,
        limits,
    ) {
        Ok(db) => db,
        Err(crate::format::xml_db::ParseXmlError::ResourceLimit(error)) => {
            return Err(DatabaseOpenError::ResourceLimit(error));
        }
        Err(error) => {
            return Err(DatabaseOpenError::Format(DatabaseFormatError::Kdbx3(
                Kdbx3OpenError::Xml(error),
            )));
        }
    };

    db.config = config;
    Ok(db)
}

#[allow(clippy::type_complexity)]
pub(crate) fn decrypt_kdbx3(
    data: &[u8],
    db_key: &DatabaseKey,
) -> Result<(DatabaseConfig, Box<dyn Cipher>, Vec<u8>), DatabaseOpenError> {
    decrypt_kdbx3_with_limits(data, db_key, DatabaseOpenLimits::default())
}

#[allow(clippy::type_complexity)]
pub(crate) fn decrypt_kdbx3_with_limits(
    data: &[u8],
    db_key: &DatabaseKey,
    limits: DatabaseOpenLimits,
) -> Result<(DatabaseConfig, Box<dyn Cipher>, Vec<u8>), DatabaseOpenError> {
    let version = DatabaseVersion::parse(data)?;
    let header = parse_outer_header(data)
        .map_err(|e| DatabaseOpenError::Format(DatabaseFormatError::Kdbx3(Kdbx3OpenError::OuterHeader(e))))?;

    let inner_decryptor = header.inner_cipher.get_cipher(&header.protected_stream_key)?;

    let config = DatabaseConfig {
        version,
        outer_cipher_config: header.outer_cipher,
        compression_config: header.compression,
        inner_cipher_config: header.inner_cipher,
        kdf_config: header.kdf_config,
        public_custom_data: Default::default(),
    };

    let mut pos = header.body_start;
    let compression = config.compression_config.get_compression();
    let payload_encrypted = data.get(pos..).ok_or(DatabaseOpenError::UnexpectedEof)?;

    let key_elements = db_key.get_key_elements()?;
    let key_elements: Vec<&[u8]> = key_elements.iter().map(|v| &v[..]).collect();
    let composite_key = calculate_sha256(&key_elements);

    let transformed_key = config
        .kdf_config
        .get_kdf_seeded(&header.transform_seed)
        .transform_key(&composite_key)?;

    let master_key = calculate_sha256(&[header.master_seed.as_ref(), &transformed_key]);

    let payload = config
        .outer_cipher_config
        .get_cipher(&master_key, header.outer_iv.as_ref())?
        .decrypt(payload_encrypted)?;

    let payload_start = payload
        .get(0..header.stream_start.len())
        .ok_or(DatabaseOpenError::UnexpectedEof)?;
    if payload_start != header.stream_start.as_slice() {
        return Err(DatabaseKeyError::IncorrectKey.into());
    }

    let mut buf = Vec::new();
    pos = 32;
    let mut block_index = 0;
    loop {
        let block_hash = payload
            .get((pos + 4)..(pos + 36))
            .ok_or(DatabaseOpenError::UnexpectedEof)?;
        let block_size = payload
            .get((pos + 36)..(pos + 40))
            .ok_or(DatabaseOpenError::UnexpectedEof)?;
        let block_size = LittleEndian::read_u32(block_size) as usize;

        if block_size == 0 {
            break;
        }

        let block_buffer_compressed = payload
            .get((pos + 40)..(pos + 40 + block_size))
            .ok_or(DatabaseOpenError::UnexpectedEof)?;

        let block_hash_check = calculate_sha256(&[block_buffer_compressed]);
        if block_hash != block_hash_check.as_slice() {
            return Err(DatabaseOpenError::Format(DatabaseFormatError::Kdbx3(
                Kdbx3OpenError::BlockHashMismatch(block_index),
            )));
        }

        buf.append(&mut block_buffer_compressed.to_vec());
        pos += 40 + block_size;
        block_index += 1;
    }

    let xml = match compression.decompress_with_limit(&buf, limits.max_decompressed_payload_bytes) {
        Ok(xml) => xml,
        Err(DecompressionError::Io(error)) => return Err(DatabaseOpenError::Io(error)),
        Err(DecompressionError::OutputLimitExceeded { .. }) => {
            return Err(DatabaseResourceLimitError::DecompressedPayloadBytes {
                limit: limits.max_decompressed_payload_bytes,
            }
            .into());
        }
    };

    Ok((config, inner_decryptor, xml))
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Kdbx3OpenError {
    #[error(transparent)]
    OuterHeader(#[from] Kdbx3OuterHeaderError),
    #[error("block hash mismatch at block index {0}")]
    BlockHashMismatch(usize),
    #[error(transparent)]
    Xml(#[from] crate::format::xml_db::ParseXmlError),
}
