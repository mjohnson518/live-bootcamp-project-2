use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub struct Password(String);

impl Password {
    pub fn parse(s: String) -> Result<Password, String> {
        if s.len() >= 8 {
            Ok(Password(s))
        } else {
            Err("Password must be at least 8 characters long".to_string())
        }
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Password {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "********")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_password() {
        assert!(Password::parse("password123".to_string()).is_ok());
    }

    #[test]
    fn invalid_password() {
        assert!(Password::parse("short".to_string()).is_err());
    }
}