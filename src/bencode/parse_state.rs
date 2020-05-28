use bytes::Bytes;
use thiserror::Error;

#[derive(Debug)]
pub struct ParseState<'a> {
    pub i: usize,
    pub bytes: &'a [u8],
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ParseErr {
    #[error("expected more bytes")]
    ExpectedMoreBytes,

    #[error("expected `{}` but found `{}` at index {2}", *.0 as char, *.1 as char)]
    ExpectedButFound(u8, u8, usize),

    #[error("could not parse `{}` at index {1} in `{2:?}`", *.0 as char)]
    CouldNotParse(u8, usize, Bytes),

    #[error("duplicate dict key `{0:?}`")]
    DuplicateDictKey(Bytes),

    #[error("error parsing int due to `{0}`")]
    ParseIntErr(#[from] std::num::ParseIntError),

    #[error("{0}")]
    Utf8strErr(#[from] std::str::Utf8Error),
}

pub type ParseResult<T> = Result<T, ParseErr>;

impl<'a> ParseState<'a> {
    pub fn new(bytes: &'a [u8]) -> ParseState {
        ParseState { i: 0, bytes }
    }

    pub fn next(&mut self) -> Result<u8, ParseErr> {
        let c = self.peek()?;
        self.i += 1;
        Ok(c)
    }

    pub fn peek(&self) -> Result<u8, ParseErr> {
        self.bytes
            .get(self.i)
            .map(|c| *c)
            .ok_or(ParseErr::ExpectedMoreBytes)
    }

    pub fn next_n(&mut self, n: usize) -> Result<&[u8], ParseErr> {
        match self.bytes.get(self.i..self.i + n) {
            Some(bytes) => {
                self.i += n;
                Ok(bytes)
            }
            None => Err(ParseErr::ExpectedMoreBytes),
        }
    }

    pub fn next_until_and_eat(&mut self, until: u8) -> Result<&[u8], ParseErr> {
        let start = self.i;
        while self.next()? != until {}
        Ok(&self.bytes[start..(self.i - 1)])
    }

    pub fn expect(&mut self, expected: u8) -> ParseResult<()> {
        let actual = self.next()?;
        if actual != expected {
            Err(ParseErr::ExpectedButFound(expected, actual, self.i - 1))
        } else {
            Ok(())
        }
    }
}
