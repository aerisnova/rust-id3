use crate::frame::Frame;
use crate::stream::encoding::Encoding;
use crate::stream::frame;
use crate::stream::tag::DecodeBudget;
use crate::tag::Version;
use crate::{Error, ErrorKind};
use byteorder::{BigEndian, WriteBytesExt};
use std::io;

pub fn decode(
    mut reader: impl io::Read,
    budget: &mut DecodeBudget,
) -> crate::Result<Option<(usize, Frame)>> {
    let mut frame_header = [0; 6];
    match reader.read_exact(&mut frame_header) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    if frame_header[0] == 0x00 {
        return Ok(None);
    }
    let id = frame::str_from_utf8(&frame_header[0..3])?;
    let sizebytes = &frame_header[3..6];
    let read_size =
        (u32::from(sizebytes[0]) << 16) | (u32::from(sizebytes[1]) << 8) | u32::from(sizebytes[2]);
    let (content, encoding) = super::content::decode(
        id,
        Version::Id3v22,
        reader.take(u64::from(read_size)),
        budget,
    )?;
    let frame = Frame::with_content(id, content).set_encoding(encoding);
    Ok(Some((6 + read_size as usize, frame)))
}

pub fn encode(mut writer: impl io::Write, frame: &Frame) -> crate::Result<usize> {
    let mut content_buf = Vec::new();
    frame::content::encode(
        &mut content_buf,
        frame.content(),
        Version::Id3v22,
        frame.encoding().unwrap_or(Encoding::UTF16),
    )?;
    assert_ne!(0, content_buf.len());
    let id = frame.id_for_version(Version::Id3v22).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "Unable to downgrade frame ID to ID3v2.2",
        )
    })?;
    assert_eq!(3, id.len());
    writer.write_all(id.as_bytes())?;
    writer.write_u24::<BigEndian>(content_buf.len() as u32)?;
    writer.write_all(&content_buf)?;
    Ok(6 + content_buf.len())
}
