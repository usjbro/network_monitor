use zeroize::Zeroize;

const MAX_HANDSHAKE_BUFFER: usize = 64 * 1024;
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeEvent {
    ClientHello {
        early_data: bool,
    },
    ServerHello {
        cipher_suite: u16,
        hello_retry_request: bool,
        tls13: bool,
    },
    Finished,
    KeyUpdate {
        request_update: bool,
    },
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeParseError {
    BufferTooLarge,
    MalformedMessage,
}

#[derive(Default)]
pub struct TlsHandshakeParser {
    buffer: Vec<u8>,
}

impl TlsHandshakeParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bytes_held(&self) -> usize {
        self.buffer.capacity()
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<HandshakeEvent>, HandshakeParseError> {
        if self.buffer.len().saturating_add(bytes.len()) > MAX_HANDSHAKE_BUFFER {
            self.buffer.zeroize();
            self.buffer = Vec::new();
            return Err(HandshakeParseError::BufferTooLarge);
        }
        self.buffer.extend_from_slice(bytes);
        let mut events = Vec::new();
        let mut consumed = 0usize;
        loop {
            let available = self.buffer.len().saturating_sub(consumed);
            if available < 4 {
                break;
            }
            let body_len = ((self.buffer[consumed + 1] as usize) << 16)
                | ((self.buffer[consumed + 2] as usize) << 8)
                | self.buffer[consumed + 3] as usize;
            let message_len = body_len
                .checked_add(4)
                .ok_or(HandshakeParseError::MalformedMessage)?;
            if message_len > MAX_HANDSHAKE_BUFFER {
                self.buffer.zeroize();
                self.buffer = Vec::new();
                return Err(HandshakeParseError::BufferTooLarge);
            }
            if available < message_len {
                break;
            }
            let event = match parse_message(
                self.buffer[consumed],
                &self.buffer[consumed + 4..consumed + message_len],
            ) {
                Ok(event) => event,
                Err(error) => {
                    self.buffer.zeroize();
                    self.buffer = Vec::new();
                    return Err(error);
                }
            };
            events.push(event);
            consumed += message_len;
        }
        if consumed > 0 {
            let remaining = self.buffer.len() - consumed;
            self.buffer.copy_within(consumed.., 0);
            self.buffer[remaining..].zeroize();
            self.buffer.truncate(remaining);
        }
        Ok(events)
    }
}

impl Drop for TlsHandshakeParser {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

fn parse_message(kind: u8, body: &[u8]) -> Result<HandshakeEvent, HandshakeParseError> {
    match kind {
        1 => parse_client_hello(body),
        2 => parse_server_hello(body),
        20 => Ok(HandshakeEvent::Finished),
        24 if body.len() == 1 && body[0] <= 1 => Ok(HandshakeEvent::KeyUpdate {
            request_update: body[0] == 1,
        }),
        24 => Err(HandshakeParseError::MalformedMessage),
        _ => Ok(HandshakeEvent::Other),
    }
}

fn parse_client_hello(body: &[u8]) -> Result<HandshakeEvent, HandshakeParseError> {
    if body.len() < 34 {
        return Err(HandshakeParseError::MalformedMessage);
    }
    let mut pos = 34;
    let session_len = *body.get(pos).ok_or(HandshakeParseError::MalformedMessage)? as usize;
    pos = pos
        .checked_add(1 + session_len)
        .ok_or(HandshakeParseError::MalformedMessage)?;
    let cipher_len = read_u16(body, pos)? as usize;
    pos = pos
        .checked_add(2 + cipher_len)
        .ok_or(HandshakeParseError::MalformedMessage)?;
    let compression_len = *body.get(pos).ok_or(HandshakeParseError::MalformedMessage)? as usize;
    pos = pos
        .checked_add(1 + compression_len)
        .ok_or(HandshakeParseError::MalformedMessage)?;
    let ext_len = read_u16(body, pos)? as usize;
    pos = pos
        .checked_add(2)
        .ok_or(HandshakeParseError::MalformedMessage)?;
    let extensions = body
        .get(pos..pos + ext_len)
        .ok_or(HandshakeParseError::MalformedMessage)?;
    if pos + ext_len != body.len() {
        return Err(HandshakeParseError::MalformedMessage);
    }
    let mut cursor = 0;
    let mut early_data = false;
    while cursor < extensions.len() {
        let header = extensions
            .get(cursor..cursor + 4)
            .ok_or(HandshakeParseError::MalformedMessage)?;
        let kind = u16::from_be_bytes([header[0], header[1]]);
        let len = u16::from_be_bytes([header[2], header[3]]) as usize;
        cursor += 4;
        let _value = extensions
            .get(cursor..cursor + len)
            .ok_or(HandshakeParseError::MalformedMessage)?;
        if kind == 42 {
            if len != 0 {
                return Err(HandshakeParseError::MalformedMessage);
            }
            early_data = true;
        }
        cursor += len;
    }
    Ok(HandshakeEvent::ClientHello { early_data })
}

fn parse_server_hello(body: &[u8]) -> Result<HandshakeEvent, HandshakeParseError> {
    if body.len() < 38 {
        return Err(HandshakeParseError::MalformedMessage);
    }
    let hrr = body.get(2..34) == Some(HRR_RANDOM.as_slice());
    let mut pos = 34;
    let session_len = *body.get(pos).ok_or(HandshakeParseError::MalformedMessage)? as usize;
    pos = pos
        .checked_add(1 + session_len)
        .ok_or(HandshakeParseError::MalformedMessage)?;
    let cipher_suite = read_u16(body, pos)?;
    pos = pos
        .checked_add(2)
        .ok_or(HandshakeParseError::MalformedMessage)?;
    let _compression = *body.get(pos).ok_or(HandshakeParseError::MalformedMessage)?;
    pos = pos
        .checked_add(1)
        .ok_or(HandshakeParseError::MalformedMessage)?;
    let mut tls13 = false;
    if pos < body.len() {
        let ext_len = read_u16(body, pos)? as usize;
        pos = pos
            .checked_add(2)
            .ok_or(HandshakeParseError::MalformedMessage)?;
        let end = pos
            .checked_add(ext_len)
            .ok_or(HandshakeParseError::MalformedMessage)?;
        let extensions = body
            .get(pos..end)
            .ok_or(HandshakeParseError::MalformedMessage)?;
        if end != body.len() {
            return Err(HandshakeParseError::MalformedMessage);
        }
        let mut cursor = 0;
        while cursor < extensions.len() {
            let header = extensions
                .get(cursor..cursor + 4)
                .ok_or(HandshakeParseError::MalformedMessage)?;
            let kind = u16::from_be_bytes([header[0], header[1]]);
            let len = u16::from_be_bytes([header[2], header[3]]) as usize;
            cursor += 4;
            let value = extensions
                .get(cursor..cursor + len)
                .ok_or(HandshakeParseError::MalformedMessage)?;
            if kind == 43 {
                tls13 = value == [3, 4];
            }
            cursor += len;
        }
    }
    Ok(HandshakeEvent::ServerHello {
        cipher_suite,
        hello_retry_request: hrr,
        tls13,
    })
}

fn read_u16(bytes: &[u8], pos: usize) -> Result<u16, HandshakeParseError> {
    let pair = bytes
        .get(
            pos..pos
                .checked_add(2)
                .ok_or(HandshakeParseError::MalformedMessage)?,
        )
        .ok_or(HandshakeParseError::MalformedMessage)?;
    Ok(u16::from_be_bytes([pair[0], pair[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshake(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![
            kind,
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ];
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn buffers_split_handshake_messages_and_detects_finished_and_key_update() {
        let mut parser = TlsHandshakeParser::new();
        assert!(parser.feed(&[20, 0]).unwrap().is_empty());
        assert_eq!(
            parser.feed(&[0, 0, 24, 0, 0, 1, 1]).unwrap(),
            vec![
                HandshakeEvent::Finished,
                HandshakeEvent::KeyUpdate {
                    request_update: true
                }
            ]
        );
    }

    #[test]
    fn extracts_server_hello_suite_and_hello_retry_request() {
        let mut body = vec![3, 3];
        body.extend_from_slice(&HRR_RANDOM);
        body.push(0); // session id
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&6u16.to_be_bytes());
        body.extend_from_slice(&[0, 43, 0, 2, 3, 4]);
        let mut parser = TlsHandshakeParser::new();
        assert_eq!(
            parser.feed(&handshake(2, &body)).unwrap(),
            vec![HandshakeEvent::ServerHello {
                cipher_suite: 0x1301,
                hello_retry_request: true,
                tls13: true
            }]
        );
    }

    #[test]
    fn detects_early_data_extension_in_client_hello() {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0x22; 32]);
        body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0, 0, 4, 0, 42, 0, 0]);
        let mut parser = TlsHandshakeParser::new();
        assert_eq!(
            parser.feed(&handshake(1, &body)).unwrap(),
            vec![HandshakeEvent::ClientHello { early_data: true }]
        );
    }

    #[test]
    fn rejects_a_declared_handshake_message_above_the_64_kib_cap() {
        let mut parser = TlsHandshakeParser::new();
        let error = parser.feed(&[1, 0x01, 0x00, 0x01]).unwrap_err();
        assert_eq!(error, HandshakeParseError::BufferTooLarge);
        assert_eq!(parser.bytes_held(), 0);
    }
}
