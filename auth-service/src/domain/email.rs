use std::fmt;
use std::hash::{Hash, Hasher};
use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, Secret};

#[derive(Debug, Clone)]
pub struct Email(Secret<String>);

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Eq for Email {}

impl Email {
    pub fn parse(s: Secret<String>) -> Result<Email> {
        if s.expose_secret().contains('@') {
            Ok(Email(s))
        } else {
            Err(eyre!("Invalid email address"))
        }
    }
}

impl AsRef<Secret<String>> for Email {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

impl fmt::Display for Email {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.expose_secret())
    }
}

impl Hash for Email {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.expose_secret().hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::Secret;

    #[test]
    fn valid_email() {
        let email = Secret::new("test@example.com".to_string());
        assert!(Email::parse(email).is_ok());
    }

    #[test]
    fn invalid_email() {
        let email = Secret::new("testexample.com".to_string());
        assert!(Email::parse(email).is_err());
    }
}