use std::fmt;

const RESERVED_LABELS: &[&str] = &["email", "phone", "name"];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Email,
    Phone,
    Name,
    Custom(String),
}

impl serde::Serialize for Kind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.as_config_value())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseKindError(pub String);

impl fmt::Display for ParseKindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ParseKindError {}

impl Kind {
    pub fn parse(raw: &str) -> Result<Self, ParseKindError> {
        let trimmed = raw.trim();
        match trimmed {
            "email" => Ok(Self::Email),
            "phone" => Ok(Self::Phone),
            "name" => Ok(Self::Name),
            other => {
                let Some(label) = other.strip_prefix("custom:") else {
                    return Err(ParseKindError(format!(
                        "unknown pseudonymize kind `{trimmed}` (supported: email, phone, name, custom:<label>)"
                    )));
                };
                validate_custom_label(label)?;
                Ok(Self::Custom(label.to_string()))
            }
        }
    }

    pub fn token_prefix(&self) -> &str {
        match self {
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Name => "name",
            Self::Custom(label) => label,
        }
    }

    pub fn as_config_value(&self) -> String {
        match self {
            Self::Email => "email".into(),
            Self::Phone => "phone".into(),
            Self::Name => "name".into(),
            Self::Custom(label) => format!("custom:{label}"),
        }
    }

    pub fn hkdf_info(&self) -> String {
        format!("shk/pseudonymize/v1/{}", self.as_config_value())
    }

    pub fn is_name(&self) -> bool {
        matches!(self, Self::Name)
    }
}

pub fn validate_custom_label(label: &str) -> Result<(), ParseKindError> {
    let valid = label
        .bytes()
        .enumerate()
        .all(|(idx, byte)| match (idx, byte) {
            (0, b'a'..=b'z') => true,
            (0, _) => false,
            (_, b'a'..=b'z' | b'0'..=b'9' | b'_') => true,
            _ => false,
        });
    if !valid || label.is_empty() || label.len() > 33 {
        return Err(ParseKindError(format!(
            "custom label `{label}` must match ^[a-z][a-z0-9_]{{0,32}}$"
        )));
    }
    if RESERVED_LABELS.contains(&label) {
        return Err(ParseKindError(format!(
            "custom label `{label}` is reserved"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_builtin_and_custom_kinds() {
        assert_eq!(Kind::parse("email").unwrap(), Kind::Email);
        assert_eq!(Kind::parse(" phone ").unwrap(), Kind::Phone);
        assert_eq!(
            Kind::parse("custom:member_id").unwrap(),
            Kind::Custom("member_id".into())
        );
    }

    #[test]
    fn rejects_reserved_and_invalid_custom_labels() {
        assert!(Kind::parse("custom:email").is_err());
        assert!(Kind::parse("custom:Foo-Bar").is_err());
        assert!(Kind::parse("custom:").is_err());
        assert!(Kind::parse("custom:1bad").is_err());
        assert!(Kind::parse("unknown").is_err());
    }

    #[test]
    fn hkdf_info_separates_custom_labels() {
        assert_eq!(Kind::Email.hkdf_info(), "shk/pseudonymize/v1/email");
        assert_eq!(
            Kind::Custom("member_id".into()).hkdf_info(),
            "shk/pseudonymize/v1/custom:member_id"
        );
    }
}
