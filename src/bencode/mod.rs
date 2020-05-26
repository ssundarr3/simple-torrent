mod parse_state;

use bytes::Bytes;
use parse_state::{ParseErr, ParseResult, ParseState};
use std::collections::BTreeMap;
use std::str;
use thiserror::Error;

const STRING_LENGTH_DATA_SEP: u8 = b':';
const INT_START: u8 = b'i';
const INT_END: u8 = b'e';
const LIST_START: u8 = b'l';
const LIST_END: u8 = b'e';
const DICT_START: u8 = b'd';
const DICT_END: u8 = b'e';

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BencodeValue {
    Int(i64),
    Bytes(Bytes),
    List(Vec<BencodeValue>),
    Dict(BencodeDict),
}

// BTreeMap is used because the keys should be in sorted order when encoding.
pub type BencodeDict = BTreeMap<Bytes, BencodeValue>;

#[derive(Error, Debug)]
pub enum GetBencodeErr {
    #[error("key `{0:?}` not found in `{1:?}`")]
    KeyNotFound(Bytes, BencodeDict),

    #[error("expected Int but found `{0:?}`")]
    ExpectedInt(BencodeValue),

    #[error("expected Str but found `{0:?}`")]
    ExpectedBytes(BencodeValue),

    #[error("expected list but found `{0:?}`")]
    ExpectedList(BencodeValue),

    #[error("expected dict but found `{0:?}`")]
    ExpectedDict(BencodeValue),

    #[error("{0}")]
    Utf8stringErr(#[from] std::string::FromUtf8Error),
}

pub trait GetFromBencodeDict {
    fn val(&self, key: &[u8]) -> Result<&BencodeValue, GetBencodeErr>;
}

impl GetFromBencodeDict for BencodeDict {
    fn val(&self, key: &[u8]) -> Result<&BencodeValue, GetBencodeErr> {
        self.get(key)
            .ok_or_else(|| GetBencodeErr::KeyNotFound(Bytes::copy_from_slice(key), self.clone()))
    }
}

impl BencodeValue {
    //
    // Getters
    //

    pub fn get_int(&self) -> Result<i64, GetBencodeErr> {
        match self {
            BencodeValue::Int(i) => Ok(*i),
            _ => Err(GetBencodeErr::ExpectedInt(self.clone())),
        }
    }

    pub fn get_bytes(&self) -> Result<&Bytes, GetBencodeErr> {
        match self {
            BencodeValue::Bytes(s) => Ok(s),
            _ => Err(GetBencodeErr::ExpectedBytes(self.clone())),
        }
    }

    pub fn get_string(&self) -> Result<String, GetBencodeErr> {
        Ok(String::from_utf8(self.get_bytes()?.to_vec())?)
    }

    pub fn get_list(&self) -> Result<&[BencodeValue], GetBencodeErr> {
        match self {
            BencodeValue::List(l) => Ok(l),
            _ => Err(GetBencodeErr::ExpectedList(self.clone())),
        }
    }

    pub fn get_strings(&self) -> Result<Vec<String>, GetBencodeErr> {
        let list = self.get_list()?;
        let mut strings = Vec::with_capacity(list.len());
        for s in list {
            strings.push(s.get_string()?)
        }
        Ok(strings)
    }

    pub fn get_dict(&self) -> Result<&BencodeDict, GetBencodeErr> {
        match self {
            BencodeValue::Dict(d) => Ok(d),
            _ => Err(GetBencodeErr::ExpectedDict(self.clone())),
        }
    }

    //
    // Encode
    //

    fn encode_bytes_(buf: &mut Vec<u8>, bytes: &Bytes) {
        buf.extend_from_slice(bytes.len().to_string().as_bytes());
        buf.push(STRING_LENGTH_DATA_SEP);
        buf.extend_from_slice(&bytes);
    }

    fn encode_(&self, buf: &mut Vec<u8>) {
        match self {
            BencodeValue::Int(i) => {
                buf.push(INT_START);
                buf.extend_from_slice(i.to_string().as_bytes());
                buf.push(INT_END);
            }
            BencodeValue::Bytes(bytes) => BencodeValue::encode_bytes_(buf, bytes),
            BencodeValue::List(list) => {
                buf.push(LIST_START);
                for item in list {
                    item.encode_(buf);
                }
                buf.push(LIST_END);
            }
            BencodeValue::Dict(ordered_dict) => {
                buf.push(DICT_START);
                for (key, value) in ordered_dict {
                    BencodeValue::encode_bytes_(buf, key);
                    value.encode_(buf);
                }
                buf.push(DICT_END);
            }
        }
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = vec![];
        self.encode_(&mut buf);
        Bytes::from(buf)
    }

    //
    // Decode
    //

    fn decode_bytes_(p: &mut ParseState) -> ParseResult<Bytes> {
        let size_str = str::from_utf8(p.next_until_and_eat(STRING_LENGTH_DATA_SEP)?)?;
        let size = size_str.parse::<usize>()?;
        let bytes = Bytes::copy_from_slice(p.next_n(size)?);
        Ok(bytes)
    }

    fn decode_(p: &mut ParseState) -> ParseResult<BencodeValue> {
        // Small errors (such as integers with leading zeroes, or the integer
        // 0 with a `-` prefixed, and dictionaries not sorted by key) in the
        // encoded bytes are ignored when parsing.
        match p.peek()? {
            INT_START => {
                p.expect(INT_START)?;
                let s = str::from_utf8(p.next_until_and_eat(INT_END)?)?;
                Ok(BencodeValue::Int(s.parse::<i64>()?))
            }
            LIST_START => {
                p.expect(LIST_START)?;
                let mut list = vec![];
                while p.peek()? != LIST_END {
                    list.push(BencodeValue::decode_(p)?);
                }
                p.expect(LIST_END)?;
                Ok(BencodeValue::List(list))
            }
            DICT_START => {
                p.expect(DICT_START)?;
                let mut dict = BTreeMap::new();
                while p.peek()? != DICT_END {
                    let key = BencodeValue::decode_bytes_(p)?;
                    let value = BencodeValue::decode_(p)?;
                    if let Some(_) = dict.insert(key.clone(), value) {
                        return Err(ParseErr::DuplicateDictKey(key));
                    }
                }
                p.expect(DICT_END)?;
                Ok(BencodeValue::Dict(dict))
            }
            c if c.is_ascii_digit() => Ok(BencodeValue::Bytes(BencodeValue::decode_bytes_(p)?)),
            c => Err(ParseErr::CouldNotParse(c, p.i)),
        }
    }

    pub fn decode(bytes: &[u8]) -> ParseResult<BencodeValue> {
        let mut p = ParseState::new(bytes);
        BencodeValue::decode_(&mut p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_encode_decode(s: &str) {
        assert_eq!(
            s.as_bytes(),
            BencodeValue::encode(&BencodeValue::decode(s.as_bytes()).unwrap())
        );
    }

    #[test]
    fn test_int() {
        assert_encode_decode("i3e");
        assert_encode_decode("i-42e");
    }

    #[test]
    fn test_bytes() {
        assert_encode_decode("5:hello");
        assert_encode_decode("1:S");
        assert_encode_decode("0:");
    }

    #[test]
    fn test_list() {
        assert_encode_decode("l5:hello4:spame");
        assert_encode_decode("le");
    }

    #[test]
    fn test_dict() {
        assert_encode_decode("d5:helloi99e2:hi1:se");
        assert_encode_decode("d4:spaml1:a1:bee");
        assert_encode_decode(
            "d9:publisher3:bob17:publisher-webpage15:www.example.com18:publisher.location4:homee",
        );
        assert_encode_decode("de");
    }
}
