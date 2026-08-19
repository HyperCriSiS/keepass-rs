use flate2::read::GzDecoder;
#[cfg(feature = "save_kdbx4")]
use flate2::write::GzEncoder;
#[cfg(feature = "save_kdbx4")]
use flate2::Compression as Flate2Compression;
use std::convert::TryFrom;
use std::io::Read;
#[cfg(feature = "save_kdbx4")]
use std::io::Write;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DecompressionError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("decompressed output exceeds configured limit of {limit} bytes")]
    OutputLimitExceeded { limit: usize },
}

pub trait Compression {
    #[cfg(feature = "save_kdbx4")]
    fn compress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error>;

    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error>;

    fn decompress_with_limit(
        &self,
        in_buffer: &[u8],
        max_output_bytes: usize,
    ) -> Result<Vec<u8>, DecompressionError>;
}

pub struct NoCompression;

impl Compression for NoCompression {
    #[cfg(feature = "save_kdbx4")]
    fn compress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        Ok(in_buffer.to_vec())
    }

    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        Ok(in_buffer.to_vec())
    }

    fn decompress_with_limit(
        &self,
        in_buffer: &[u8],
        max_output_bytes: usize,
    ) -> Result<Vec<u8>, DecompressionError> {
        if in_buffer.len() > max_output_bytes {
            return Err(DecompressionError::OutputLimitExceeded {
                limit: max_output_bytes,
            });
        }

        Ok(in_buffer.to_vec())
    }
}

pub struct GZipCompression;

impl Compression for GZipCompression {
    #[cfg(feature = "save_kdbx4")]
    fn compress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let mut res = Vec::new();
        let mut encoder = GzEncoder::new(&mut res, Flate2Compression::default());
        encoder.write_all(in_buffer)?;
        encoder.flush()?;
        encoder.finish()?;
        Ok(res)
    }

    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let mut res = Vec::new();
        let mut decoder = GzDecoder::new(in_buffer);
        decoder.read_to_end(&mut res)?;
        Ok(res)
    }

    fn decompress_with_limit(
        &self,
        in_buffer: &[u8],
        max_output_bytes: usize,
    ) -> Result<Vec<u8>, DecompressionError> {
        let mut res = Vec::new();
        let decoder = GzDecoder::new(in_buffer);
        let read_limit = u64::try_from(max_output_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let mut limited = decoder.take(read_limit);
        limited.read_to_end(&mut res)?;

        if res.len() > max_output_bytes {
            return Err(DecompressionError::OutputLimitExceeded {
                limit: max_output_bytes,
            });
        }

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::{Compression as _, DecompressionError, GZipCompression, NoCompression};
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn gzip_decompression_accepts_exact_limit() {
        let input = vec![b'A'; 1024];
        let compressed = gzip(&input);

        let decoded = GZipCompression
            .decompress_with_limit(&compressed, input.len())
            .unwrap();

        assert_eq!(decoded, input);
    }

    #[test]
    fn gzip_decompression_rejects_output_over_limit() {
        let input = vec![b'A'; 1025];
        let compressed = gzip(&input);

        let error = GZipCompression
            .decompress_with_limit(&compressed, 1024)
            .unwrap_err();

        assert!(matches!(
            error,
            DecompressionError::OutputLimitExceeded { limit: 1024 }
        ));
    }

    #[test]
    fn no_compression_rejects_input_over_limit() {
        let error = NoCompression
            .decompress_with_limit(&[0_u8; 2], 1)
            .unwrap_err();

        assert!(matches!(
            error,
            DecompressionError::OutputLimitExceeded { limit: 1 }
        ));
    }
}
