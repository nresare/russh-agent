// Copyright (c) 2020 russh-agent developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `russh-agent` utility functions

use crate::error::Result;
use bytes::BufMut;
#[cfg(test)]
use hxdmp::hexdump;
#[cfg(test)]
use slog::{info, trace, Level, Logger};
use std::convert::TryInto;

crate fn put_string<T>(buffer: &mut T, bytes: &[u8]) -> Result<()>
where
    T: BufMut,
{
    let str_len = bytes.len();
    buffer.put_u32(usize::try_into(str_len)?);
    buffer.put_slice(bytes);
    Ok(())
}

#[cfg(test)]
crate fn hexy(prefix: &str, logger: &Logger, buf: &[u8]) -> Result<()> {
    hexyl(prefix, logger, buf, Some(Level::Trace))
}

#[cfg(test)]
crate fn hexyl(prefix: &str, logger: &Logger, buf: &[u8], level: Option<Level>) -> Result<()> {
    let mut hexbuf = vec![];
    hexdump(&buf, &mut hexbuf)?;
    if let Some(level) = level {
        match level {
            Level::Info => info!(logger, "{}\n{}", prefix, String::from_utf8_lossy(&hexbuf)),
            _ => trace!(logger, "{}\n{}", prefix, String::from_utf8_lossy(&hexbuf)),
        }
    } else {
        trace!(logger, "{}\n{}", prefix, String::from_utf8_lossy(&hexbuf));
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::put_string;
    use crate::error::Result;
    use bytes::BytesMut;

    #[test]
    fn put_string_works() -> Result<()> {
        let test_str = "this is a test string!";
        let mut buffer = BytesMut::new();
        put_string(&mut buffer, test_str.as_bytes())?;
        let mut expected = vec![0, 0, 0, 22];
        expected.extend(test_str.as_bytes());
        assert_eq!(expected, buffer);
        buffer.clear();
        expected.clear();

        put_string(&mut buffer, b"")?;
        expected.extend(&[0, 0, 0, 0]);
        assert_eq!(expected, buffer);
        Ok(())
    }
}
