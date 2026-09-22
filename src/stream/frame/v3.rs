use crate::frame::Frame;
use crate::stream::encoding::Encoding;
use crate::stream::frame;
use crate::tag::Version;
use crate::{Error, ErrorKind};
use bitflags::bitflags;
use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use flate2::Compression;
use flate2::write::ZlibEncoder;
use std::io;

bitflags! {
    pub struct Flags: u16 {
        const TAG_ALTER_PRESERVATION  = 0x8000;
        const FILE_ALTER_PRESERVATION = 0x4000;
        const READ_ONLY               = 0x2000;
        const COMPRESSION             = 0x0080;
        const ENCRYPTION              = 0x0040;
        const GROUPING_IDENTITY       = 0x0020;
    }
}

pub fn decode(mut reader: impl io::Read) -> crate::Result<Option<(usize, Frame)>> {
    let mut frame_header = [0; 10];
    match reader.read_exact(&mut frame_header) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    if frame_header[0] == 0x00 {
        return Ok(None);
    }
    let id = frame::str_from_utf8(&frame_header[0..4])?;

    let content_size = BigEndian::read_u32(&frame_header[4..8]) as usize;
    let flags = Flags::from_bits_truncate(BigEndian::read_u16(&frame_header[8..10]));
    if flags.contains(Flags::ENCRYPTION) {
        return Err(Error::new(
            ErrorKind::UnsupportedFeature,
            "encryption is not supported",
        ));
    } else if flags.contains(Flags::GROUPING_IDENTITY) {
        return Err(Error::new(
            ErrorKind::UnsupportedFeature,
            "grouping identity is not supported",
        ));
    }

    let read_size = if flags.contains(Flags::COMPRESSION) {
        let _decompressed_size = reader.read_u32::<BigEndian>()?;
        content_size
            .checked_sub(4)
            .ok_or_else(|| Error::new(ErrorKind::Parsing, "Insufficient data to decode bytes"))?
    } else {
        content_size
    };
    let mut content_buf = vec![0; read_size];
    reader.read_exact(&mut content_buf)?;
    let (content, encoding) = super::decode_content(
        &content_buf[..],
        Version::Id3v23,
        id,
        flags.contains(Flags::COMPRESSION),
        false,
    )?;
    let frame = Frame::with_content(id, content).set_encoding(encoding);
    Ok(Some((10 + content_size, frame)))
}

pub fn encode(mut writer: impl io::Write, frame: &Frame, flags: Flags) -> crate::Result<usize> {
    let (content_buf, comp_hint_delta, decompressed_size) = if flags.contains(Flags::COMPRESSION) {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        let content_size = frame::content::encode(
            &mut encoder,
            frame.content(),
            Version::Id3v23,
            frame.encoding().unwrap_or(Encoding::UTF16),
        )?;
        let content_buf = encoder.finish()?;
        (content_buf, 4, Some(content_size))
    } else {
        let mut content_buf = Vec::new();
        frame::content::encode(
            &mut content_buf,
            frame.content(),
            Version::Id3v23,
            frame.encoding().unwrap_or(Encoding::UTF16),
        )?;
        (content_buf, 0, None)
    };

    writer.write_all({
        let id = frame.id().as_bytes();
        if id.len() != 4 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Frame ID must be 4 bytes long",
            ));
        }
        id
    })?;
    writer.write_u32::<BigEndian>((content_buf.len() + comp_hint_delta) as u32)?;
    writer.write_u16::<BigEndian>(flags.bits())?;
    if let Some(s) = decompressed_size {
        writer.write_u32::<BigEndian>(s as u32)?;
    }
    writer.write_all(&content_buf)?;
    Ok(10 + comp_hint_delta + content_buf.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::Content;
    use std::io::Cursor;

    #[test]
    fn test_encode_with_invalid_frame_id() {
        let frame = Frame::with_content("TST", Content::Text("Test content".to_string()));
        let flags = Flags::empty();
        let mut writer = Cursor::new(Vec::new());

        let result = encode(&mut writer, &frame, flags);

        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e.kind, ErrorKind::InvalidInput));
            assert_eq!(e.description, "Frame ID must be 4 bytes long");
        }
    }

    #[test]
    fn test_decode_with_underflow() {
        // ID3v2.3 frame header: COMPRESSION flag (0x0080) set with a content
        // size of 3 (< the 4-byte decompressed-size prefix). In v2.3 the frame
        // size is a raw big-endian u32.
        let frame_header = [
            b'T', b'E', b'S', b'T', // Frame ID
            0x00, 0x00, 0x00, 0x03, // Content size (3 bytes)
            0x00, 0x80, // Flags (COMPRESSION)
        ];
        // Frame header followed by the 4-byte decompressed-size prefix.
        let mut data = Vec::new();
        data.extend_from_slice(&frame_header);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // Decompressed size (4 bytes)

        let mut reader = Cursor::new(data);

        // Attempt to decode the frame
        let result = decode(&mut reader);

        // Ensure that the result is an error due to underflow
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e.kind, ErrorKind::Parsing));
            assert_eq!(e.description, "Insufficient data to decode bytes");
        }
    }
}
