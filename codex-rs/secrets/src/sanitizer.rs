use regex::Regex;
use std::sync::LazyLock;

static OPENAI_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| compile_regex(r"sk-[A-Za-z0-9]{20,}"));
static AWS_ACCESS_KEY_ID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| compile_regex(r"\bAKIA[0-9A-Z]{16}\b"));
static AWS_SECRET_ACCESS_KEY_ASSIGNMENT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(r#"(?i)\b(aws_secret_access_key)\b(\s*[:=]\s*)(["']?)[A-Za-z0-9/+]{40}"#)
});
static BEARER_TOKEN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| compile_regex(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{16,}\b"));
static GITHUB_TOKEN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| compile_regex(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"));
static JWT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
});
static SECRET_ASSIGNMENT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(
        r#"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|refresh[_-]?token|token|secret|password)\b(\s*[:=]\s*)(["']?)[^\s"']{8,}"#,
    )
});
static PRIVATE_KEY_BLOCK_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    compile_regex(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----")
});

/// Remove secret and keys from a String. This is done on best effort basis following some
/// well-known REGEX.
pub fn redact_secrets(input: String) -> String {
    let redacted = OPENAI_KEY_REGEX.replace_all(&input, "[REDACTED_SECRET]");
    let redacted = AWS_ACCESS_KEY_ID_REGEX.replace_all(&redacted, "[REDACTED_SECRET]");
    let redacted =
        AWS_SECRET_ACCESS_KEY_ASSIGNMENT_REGEX.replace_all(&redacted, "$1$2$3[REDACTED_SECRET]");
    let redacted = BEARER_TOKEN_REGEX.replace_all(&redacted, "Bearer [REDACTED_SECRET]");
    let redacted = GITHUB_TOKEN_REGEX.replace_all(&redacted, "[REDACTED_SECRET]");
    let redacted = JWT_REGEX.replace_all(&redacted, "[REDACTED_SECRET]");
    let redacted = SECRET_ASSIGNMENT_REGEX.replace_all(&redacted, "$1$2$3[REDACTED_SECRET]");
    let redacted = PRIVATE_KEY_BLOCK_REGEX.replace_all(&redacted, "[REDACTED_PRIVATE_KEY]");

    redacted.to_string()
}

fn compile_regex(pattern: &str) -> Regex {
    match Regex::new(pattern) {
        Ok(regex) => regex,
        // Panic is ok thanks to `load_regex` test.
        Err(err) => panic!("invalid regex pattern `{pattern}`: {err}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_regex() {
        // The goal of this test is just to compile all the regex to prevent the panic
        let _ = redact_secrets("secret".to_string());
    }

    #[test]
    fn redacts_common_secret_shapes() {
        let input = [
            "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz",
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "github=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL",
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
            "token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue",
            "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----",
        ]
        .join("\n");

        let redacted = redact_secrets(input);

        assert!(!redacted.contains("sk-abcdefghijklmnopqrstuvwxyz"));
        assert!(!redacted.contains("wJalrXUtnFEMI"));
        assert!(!redacted.contains("ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL"));
        assert!(!redacted.contains("abcdefghijklmnopqrstuvwxyz"));
        assert!(!redacted.contains("eyJhbGciOiJIUzI1NiJ9"));
        assert!(!redacted.contains("BEGIN PRIVATE KEY"));
    }
}
