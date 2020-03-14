// Copyright (c) 2020 tussh developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Error Codes
use std::fmt;

/// Error Codes
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
crate enum ErrCode {
    /// An environmental error
    Env,
    /// An I/O error
    Io,
    /// A parsing error
    Parse,
    /// A protocol error
    Protocol,
    /// An unknown
    Unknown,
}

impl fmt::Display for ErrCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Env => "env",
                Self::Io => "io",
                Self::Parse => "parse",
                Self::Protocol => "protocol",
                Self::Unknown => "unknown",
            }
        )
    }
}

impl Into<&str> for ErrCode {
    #[must_use]
    fn into(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::Io => "io",
            Self::Parse => "parse",
            Self::Protocol => "protocol",
            Self::Unknown => "unknown",
        }
    }
}

impl Into<String> for ErrCode {
    #[must_use]
    fn into(self) -> String {
        let tmp: &str = self.into();
        tmp.to_string()
    }
}

impl From<&str> for ErrCode {
    #[must_use]
    fn from(text: &str) -> Self {
        match text {
            "env" => Self::Env,
            "io" => Self::Io,
            "parse" => Self::Parse,
            "protocol" => Self::Protocol,
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod test {
    use super::ErrCode;
    use crate::error::Result;
    use lazy_static::lazy_static;
    use std::fmt;

    lazy_static! {
        static ref TEST_CASE_1: (&'static str, ErrCode) = ("env", ErrCode::Env);
        static ref TEST_CASE_2: (&'static str, ErrCode) = ("io", ErrCode::Io);
        static ref TEST_CASE_3: (&'static str, ErrCode) = ("parse", ErrCode::Parse);
        static ref TEST_CASE_4: (&'static str, ErrCode) = ("protocol", ErrCode::Protocol);
        static ref TEST_CASE_5: (&'static str, ErrCode) = ("unknown", ErrCode::Unknown);
        static ref TEST_CASES: Vec<(&'static str, ErrCode)> = {
            let mut test_cases = Vec::new();
            test_cases.push(*TEST_CASE_1);
            test_cases.push(*TEST_CASE_2);
            test_cases.push(*TEST_CASE_3);
            test_cases.push(*TEST_CASE_4);
            test_cases.push(*TEST_CASE_5);
            test_cases
        };
    }

    #[test]
    fn into_err_code() {
        for (s, err_code) in &*TEST_CASES {
            let actual: &str = (*err_code).into();
            assert_eq!(&actual, s);
            let actual_s: String = (*err_code).into();
            assert_eq!(actual_s, s.to_string());
        }
    }

    #[test]
    fn from_str() {
        for (s, err_code) in &*TEST_CASES {
            let actual = ErrCode::from(*s);
            assert_eq!(actual, *err_code);
        }

        assert_eq!(ErrCode::from("blah"), ErrCode::Unknown);
    }

    #[test]
    fn display() -> Result<()> {
        let mut buf = String::new();

        for (s, err_code) in &*TEST_CASES {
            fmt::write(&mut buf, format_args!("{}", err_code))?;
            assert_eq!(buf, (*s).to_string());
            buf.clear();
        }
        Ok(())
    }
}
