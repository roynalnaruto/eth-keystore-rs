#[derive(Debug, PartialEq)]
pub enum Error {
    MacMismatch,
    StdIo(String),
    SerdeJson(String),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::StdIo(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::SerdeJson(e.to_string())
    }
}
