//! Newline-delimited framing with a hard per-line size limit. A peer that
//! never sends a newline cannot make us buffer unbounded memory.

use std::io::{BufRead, ErrorKind};

#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    Line(Vec<u8>),
    TooLong,
}

pub struct BoundedLines<R: BufRead> {
    r: R,
    max: usize,
    done: bool,
}

impl<R: BufRead> BoundedLines<R> {
    pub fn new(r: R, max: usize) -> Self {
        Self { r, max, done: false }
    }
}

impl<R: BufRead> Iterator for BoundedLines<R> {
    type Item = std::io::Result<Frame>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buf: Vec<u8> = Vec::new();
        let mut too_long = false;
        loop {
            if self.done {
                return None;
            }
            let available = match self.r.fill_buf() {
                Ok(b) => b,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Some(Err(e)),
            };
            if available.is_empty() {
                // EOF: flush a trailing partial line.
                self.done = true;
                if too_long {
                    return Some(Ok(Frame::TooLong));
                }
                let line = trim(&buf);
                if line.is_empty() {
                    return None;
                }
                return Some(Ok(Frame::Line(line.to_vec())));
            }
            let (chunk, found_newline) = match available.iter().position(|&b| b == b'\n') {
                Some(i) => (&available[..i], Some(i)),
                None => (available, None),
            };
            if !too_long {
                if buf.len() + chunk.len() > self.max {
                    too_long = true;
                    buf = Vec::new(); // release memory immediately
                } else {
                    buf.extend_from_slice(chunk);
                }
            }
            let consumed = found_newline.map_or(available.len(), |i| i + 1);
            self.r.consume(consumed);
            if found_newline.is_some() {
                if too_long {
                    return Some(Ok(Frame::TooLong));
                }
                let line = trim(&buf);
                if line.is_empty() {
                    buf.clear();
                    continue;
                }
                return Some(Ok(Frame::Line(line.to_vec())));
            }
        }
    }
}

fn trim(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map_or(start, |i| i + 1);
    &b[start..end.max(start)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn frames(input: &[u8], max: usize) -> Vec<Frame> {
        BoundedLines::new(Cursor::new(input.to_vec()), max)
            .map(Result::unwrap)
            .collect()
    }

    #[test]
    fn splits_lines_and_strips_crlf() {
        assert_eq!(
            frames(b"a\r\nbb\nccc", 10),
            vec![
                Frame::Line(b"a".to_vec()),
                Frame::Line(b"bb".to_vec()),
                Frame::Line(b"ccc".to_vec())
            ]
        );
    }

    #[test]
    fn skips_blank_lines() {
        assert_eq!(frames(b"\n  \r\na\n", 10), vec![Frame::Line(b"a".to_vec())]);
    }

    #[test]
    fn oversize_line_is_discarded_and_stream_resyncs() {
        let mut input = vec![b'x'; 50];
        input.extend_from_slice(b"\nok\n");
        assert_eq!(frames(&input, 10), vec![Frame::TooLong, Frame::Line(b"ok".to_vec())]);
    }

    #[test]
    fn oversize_without_newline_ends_as_too_long() {
        assert_eq!(frames(&[b'y'; 100], 10), vec![Frame::TooLong]);
    }

    #[test]
    fn small_buffer_reader_still_works() {
        let r = std::io::BufReader::with_capacity(2, Cursor::new(b"hello\nworld\n".to_vec()));
        let got: Vec<Frame> = BoundedLines::new(r, 100).map(Result::unwrap).collect();
        assert_eq!(
            got,
            vec![Frame::Line(b"hello".to_vec()), Frame::Line(b"world".to_vec())]
        );
    }
}
