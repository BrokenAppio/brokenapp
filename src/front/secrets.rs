//! Keeping secret values out of `.brokenapp/config.toml` and out of every
//! command `init`, `map` and `doctor` echo.
//!
//! A dev command such as
//! `DATABASE_URL=postgres://app:pw@localhost/app OPENAI_API_KEY=sk-.. npm run dev`
//! carries secrets in inline `NAME=value` assignments. `init` moves those to
//! `[project] dev_env` as `"env:NAME"` references (when the caller's shell
//! exports the same value) or refuses with instructions; the echoed form of a
//! command always has assignment values and URL passwords replaced by `***`.
//!
//! The command is analyzed with a small shell lexer that keeps byte spans, so
//! removing an assignment leaves the rest of the command byte-for-byte intact
//! (`$PORT` expansions, quoting and operators are untouched).

use std::fmt::Write as _;

/// Replacement shown instead of a redacted value.
pub const REDACTED: &str = "***";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    /// A shell word: byte span in the command plus its unquoted text.
    Word {
        start: usize,
        end: usize,
        text: String,
    },
    /// An operator that ends a simple command (`&&`, `||`, `;`, `|`, `&`,
    /// newline, parentheses) or a redirection.
    Op { start: usize, end: usize },
}

/// Split `cmd` into words and operators, keeping byte spans. Quotes and
/// backslash escapes follow POSIX `sh` rules closely enough for dev commands;
/// an unterminated quote runs to the end of the string.
fn lex(cmd: &str) -> Vec<Tok> {
    let bytes = cmd.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0;
    let mut word: Option<(usize, String)> = None;
    let end_word = |word: &mut Option<(usize, String)>, toks: &mut Vec<Tok>, end: usize| {
        if let Some((start, text)) = word.take() {
            toks.push(Tok::Word { start, end, text });
        }
    };
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b' ' | b'\t' | b'\r' => {
                end_word(&mut word, &mut toks, i);
                i += 1;
            }
            b'\n' | b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>' => {
                end_word(&mut word, &mut toks, i);
                let mut j = i + 1;
                if matches!(c, b'&' | b'|' | b'>' | b'<') && bytes.get(j) == Some(&c) {
                    j += 1;
                }
                toks.push(Tok::Op { start: i, end: j });
                i = j;
            }
            b'\'' => {
                let w = word.get_or_insert_with(|| (i, String::new()));
                let close = cmd[i + 1..].find('\'').map(|k| i + 1 + k);
                let stop = close.unwrap_or(bytes.len());
                w.1.push_str(&cmd[i + 1..stop]);
                i = close.map_or(bytes.len(), |k| k + 1);
            }
            b'"' => {
                let w = word.get_or_insert_with(|| (i, String::new()));
                let mut j = i + 1;
                let mut closed = false;
                while j < bytes.len() {
                    match bytes[j] {
                        b'"' => {
                            closed = true;
                            break;
                        }
                        b'\\'
                            if j + 1 < bytes.len()
                                && matches!(bytes[j + 1], b'"' | b'\\' | b'$' | b'`') =>
                        {
                            w.1.push(bytes[j + 1] as char);
                            j += 2;
                        }
                        _ => {
                            let ch = cmd[j..].chars().next().unwrap_or(' ');
                            w.1.push(ch);
                            j += ch.len_utf8();
                        }
                    }
                }
                i = if closed { j + 1 } else { bytes.len() };
            }
            b'\\' => {
                let w = word.get_or_insert_with(|| (i, String::new()));
                if let Some(ch) = cmd[i + 1..].chars().next() {
                    if ch != '\n' {
                        w.1.push(ch);
                    }
                    i += 1 + ch.len_utf8();
                } else {
                    i += 1;
                }
            }
            _ => {
                let ch = cmd[i..].chars().next().unwrap_or(' ');
                word.get_or_insert_with(|| (i, String::new())).1.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    end_word(&mut word, &mut toks, bytes.len());
    toks
}

/// `NAME=value` when the raw word starts with an unquoted variable name and `=`.
fn assignment_parts<'a>(raw: &str, text: &'a str) -> Option<(&'a str, &'a str)> {
    let name_len = raw
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
        .count();
    if name_len == 0
        || raw.as_bytes()[0].is_ascii_digit()
        || raw.as_bytes().get(name_len) != Some(&b'=')
    {
        return None;
    }
    let (name, rest) = text.split_at(name_len);
    Some((name, rest.strip_prefix('=').unwrap_or(rest)))
}

/// Words that keep the following words in "assignment position".
fn is_env_prefix(word: &str) -> bool {
    let bin = std::path::Path::new(word)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(word);
    matches!(bin, "env" | "cross-env" | "cross-env-shell" | "export")
}

/// How sensitive an inline value is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    /// Must never be written to config.toml or printed.
    Secret,
    /// Not a known secret, but not known to be harmless either: kept in the
    /// config when given, redacted when echoed.
    Unknown,
    /// Harmless (ports, hosts, modes, feature flags, telemetry switches):
    /// kept and shown.
    Public,
}

/// Name tokens (split on `_`) that mark a secret.
const SECRET_NAME_TOKENS: &[&str] = &[
    "KEY",
    "KEYS",
    "APIKEY",
    "SECRET",
    "SECRETS",
    "TOKEN",
    "TOKENS",
    "PASSWORD",
    "PASSWD",
    "PASS",
    "PWD",
    "CREDENTIAL",
    "CREDENTIALS",
    "PRIVATE",
    "DSN",
    "SALT",
    "COOKIE",
    "SIGNING",
];
/// Name substrings that mark a secret even inside a longer token (`GITHUBTOKEN`).
const SECRET_NAME_PARTS: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "APIKEY",
    "API_KEY",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "DATABASE",
    "CONNECTION_STRING",
    "CONN_STR",
];
/// Connection-string variables: secret even without a password in the value.
const CONNECTION_NAMES: &[&str] = &[
    "DB_URL",
    "DB_URI",
    "REDIS_URL",
    "MONGO_URL",
    "MONGO_URI",
    "MONGODB_URL",
    "MONGODB_URI",
    "POSTGRES_URL",
    "MYSQL_URL",
    "AMQP_URL",
    "RABBITMQ_URL",
];
/// Variables that are harmless to keep inline and to print.
const PUBLIC_NAMES: &[&str] = &[
    "PORT",
    "HOST",
    "HOSTNAME",
    "NODE_ENV",
    "APP_ENV",
    "BROWSER",
    "CI",
    "DEBUG",
    "FORCE_COLOR",
    "NO_COLOR",
    "TZ",
    "LANG",
    "LC_ALL",
    "NODE_OPTIONS",
    "BASE_PATH",
    "PUBLIC_URL",
    "WATCHPACK_POLLING",
    "CHOKIDAR_USEPOLLING",
];
/// Name suffixes that mark harmless switches.
const PUBLIC_SUFFIXES: &[&str] = &[
    "_ENABLED",
    "_DISABLED",
    "_ENABLE",
    "_DISABLE",
    "_PORT",
    "_HOST",
    "_MODE",
    "_ENV",
    "_LEVEL",
    "_DEBUG",
    "_POLLING",
];

/// Classify an inline `NAME=value` assignment.
pub fn classify(name: &str, value: &str) -> Sensitivity {
    if value.trim().is_empty() {
        // An empty value disables something; there is nothing to leak.
        return Sensitivity::Public;
    }
    let upper = name.to_ascii_uppercase();
    if url_has_userinfo(value) || looks_like_token(value) {
        return Sensitivity::Secret;
    }
    if looks_like_path(value) {
        // `SSL_KEY_FILE=./certs/key.pem`: a location, not the secret itself.
        return Sensitivity::Unknown;
    }
    if PUBLIC_NAMES.contains(&upper.as_str())
        || upper.contains("TELEMETRY")
        || PUBLIC_SUFFIXES.iter().any(|s| upper.ends_with(s))
    {
        return Sensitivity::Public;
    }
    let tokens: Vec<&str> = upper.split('_').filter(|t| !t.is_empty()).collect();
    let pwd_alone = matches!(upper.as_str(), "PWD" | "OLDPWD");
    if (!pwd_alone && tokens.iter().any(|t| SECRET_NAME_TOKENS.contains(t)))
        || SECRET_NAME_PARTS.iter().any(|p| upper.contains(p))
        || CONNECTION_NAMES
            .iter()
            .any(|c| upper == *c || upper.ends_with(&format!("_{c}")))
    {
        return Sensitivity::Secret;
    }
    if is_plain_scalar(value) {
        return Sensitivity::Public;
    }
    Sensitivity::Unknown
}

/// A file path (`./key.pem`, `/etc/app/creds.json`, `file:./dev.db`).
fn looks_like_path(value: &str) -> bool {
    let v = value.trim();
    !v.contains("://")
        && ["/", "./", "../", "~/", "file:"]
            .iter()
            .any(|p| v.starts_with(p))
}

/// Booleans and numbers cannot carry a secret.
fn is_plain_scalar(value: &str) -> bool {
    let v = value.trim();
    matches!(
        v.to_ascii_lowercase().as_str(),
        "true" | "false" | "yes" | "no" | "on" | "off"
    ) || (!v.is_empty() && v.len() <= 6 && v.bytes().all(|b| b.is_ascii_digit()))
}

/// Well-known secret value shapes: API key prefixes, JWTs, PEM blocks.
fn looks_like_token(value: &str) -> bool {
    let v = value.trim();
    const PREFIXES: &[&str] = &[
        "sk-",
        "sk_live_",
        "sk_test_",
        "rk_live_",
        "pk_live_",
        "ghp_",
        "gho_",
        "ghs_",
        "ghu_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "xoxr-",
        "glpat-",
        "-----BEGIN",
    ];
    let aws_key_id = (v.starts_with("AKIA") || v.starts_with("ASIA"))
        && v.len() == 20
        && v.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
    PREFIXES.iter().any(|p| v.starts_with(p))
        || aws_key_id
        || (v.starts_with("AIza") && v.len() >= 30)
        || (v.starts_with("eyJ") && v.len() > 30 && v.matches('.').count() == 2)
}

/// A URL with a user (and usually a password) before the host:
/// `postgres://app:pw@localhost/db`.
pub fn url_has_userinfo(value: &str) -> bool {
    url_userinfo_span(value).is_some()
}

/// Byte span of the `user[:password]` part of the first URL in `value`.
fn url_userinfo_span(value: &str) -> Option<(usize, usize)> {
    let scheme_end = value.find("://")?;
    let scheme = &value[..scheme_end];
    let scheme_start = scheme
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
        .map_or(0, |i| i + 1);
    if scheme_start == scheme_end {
        return None;
    }
    let auth_start = scheme_end + 3;
    let rest = &value[auth_start..];
    let authority_len = rest.find(['/', '?', '#', ' ']).unwrap_or(rest.len());
    let at = rest[..authority_len].rfind('@')?;
    (at > 0).then_some((auth_start, auth_start + at))
}

/// `postgres://app:pw@host/db` -> `postgres://app:***@host/db`; a URL with a
/// user but no password keeps the user.
pub fn redact_url_credentials(value: &str) -> String {
    let Some((start, end)) = url_userinfo_span(value) else {
        return value.to_string();
    };
    let userinfo = &value[start..end];
    let redacted = match userinfo.split_once(':') {
        Some((user, _)) => format!("{user}:{REDACTED}"),
        None => userinfo.to_string(),
    };
    format!("{}{redacted}{}", &value[..start], &value[end..])
}

/// One sensitive item found in a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Variable or flag name (`DATABASE_URL`, `--api-key`).
    pub name: String,
    /// `assignment`, `flag`, or `url`.
    pub kind: &'static str,
    pub sensitivity: Sensitivity,
    value: String,
    /// Span of the whole word (assignment) or of the value to redact.
    word: (usize, usize),
    value_span: (usize, usize),
}

impl Finding {
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// Analysis of a shell command.
#[derive(Debug, Clone)]
pub struct CommandScan {
    cmd: String,
    toks: Vec<Tok>,
    /// Inline env assignments (any sensitivity), in order.
    pub assignments: Vec<Finding>,
    /// Secret flags (`--api-key x`) and credential URLs outside assignments.
    pub inline_credentials: Vec<Finding>,
}

/// Flag names (split on `-`/`_`) that carry a secret value.
fn is_secret_flag(flag: &str) -> bool {
    let name = flag
        .trim_start_matches('-')
        .to_ascii_uppercase()
        .replace('-', "_");
    !name.is_empty() && classify(&name, "x") == Sensitivity::Secret
}

pub fn scan(cmd: &str) -> CommandScan {
    let toks = lex(cmd);
    let mut assignments = Vec::new();
    let mut inline_credentials = Vec::new();
    // At the start of a simple command, assignments and env prefixes come first.
    let mut expect_cmd = true;
    let mut env_prefix = false;
    let mut pending_flag: Option<(String, (usize, usize))> = None;
    for tok in &toks {
        let (start, end, text) = match tok {
            Tok::Op { .. } => {
                expect_cmd = true;
                env_prefix = false;
                pending_flag = None;
                continue;
            }
            Tok::Word { start, end, text } => (*start, *end, text.as_str()),
        };
        let raw = &cmd[start..end];
        if expect_cmd || env_prefix {
            let parts = assignment_parts(raw, text)
                .or_else(|| env_prefix.then(|| assignment_parts(text, text)).flatten());
            if let Some((name, value)) = parts {
                let value_start = raw
                    .find('=')
                    .map_or(start + name.len() + 1, |i| start + i + 1);
                let value_end = if raw.len() >= 2
                    && ((raw.starts_with('\'') && raw.ends_with('\''))
                        || (raw.starts_with('"') && raw.ends_with('"')))
                {
                    end.saturating_sub(1)
                } else {
                    end
                };
                assignments.push(Finding {
                    name: name.to_string(),
                    kind: "assignment",
                    sensitivity: classify(name, value),
                    value: value.to_string(),
                    word: (start, end),
                    value_span: (value_start.min(value_end), value_end),
                });
                continue;
            }
            if is_env_prefix(text) {
                env_prefix = true;
                expect_cmd = false;
                continue;
            }
            if env_prefix && text.starts_with('-') {
                // `env -i`, `env -u NAME`: options of the prefix itself.
                continue;
            }
            expect_cmd = false;
            env_prefix = false;
        }
        if let Some((flag, word)) = pending_flag.take() {
            if !text.starts_with('-') && !looks_like_path(text) {
                inline_credentials.push(Finding {
                    name: flag,
                    kind: "flag",
                    sensitivity: Sensitivity::Secret,
                    value: text.to_string(),
                    word,
                    value_span: (start, end),
                });
                continue;
            }
        }
        if text.starts_with("--") || (text.starts_with('-') && text.len() > 2) {
            match text.split_once('=') {
                Some((flag, value))
                    if is_secret_flag(flag) && !value.is_empty() && !looks_like_path(value) =>
                {
                    let value_start = raw.find('=').map_or(start, |i| start + i + 1);
                    inline_credentials.push(Finding {
                        name: flag.to_string(),
                        kind: "flag",
                        sensitivity: Sensitivity::Secret,
                        value: value.to_string(),
                        word: (start, end),
                        value_span: (value_start, end),
                    });
                    continue;
                }
                None if is_secret_flag(text) => {
                    pending_flag = Some((text.to_string(), (start, end)));
                    continue;
                }
                _ => {}
            }
        }
        if url_has_userinfo(text) {
            inline_credentials.push(Finding {
                name: "URL with credentials".to_string(),
                kind: "url",
                sensitivity: Sensitivity::Secret,
                value: text.to_string(),
                word: (start, end),
                value_span: (start, end),
            });
        }
    }
    CommandScan {
        cmd: cmd.to_string(),
        toks,
        assignments,
        inline_credentials,
    }
}

impl CommandScan {
    /// Secret inline assignments.
    pub fn secret_assignments(&self) -> impl Iterator<Item = &Finding> {
        self.assignments
            .iter()
            .filter(|a| a.sensitivity == Sensitivity::Secret)
    }

    /// Whether the command carries any secret value.
    pub fn has_secrets(&self) -> bool {
        self.secret_assignments().next().is_some() || !self.inline_credentials.is_empty()
    }

    /// Names of the secret values (never the values), for messages.
    pub fn secret_names(&self) -> Vec<String> {
        self.secret_assignments()
            .chain(self.inline_credentials.iter())
            .map(|f| f.name.clone())
            .collect()
    }

    /// The command for display: values of every non-public assignment and
    /// secret flag, and URL passwords, replaced by `***`.
    pub fn redacted(&self) -> String {
        let mut edits: Vec<((usize, usize), String)> = Vec::new();
        for a in &self.assignments {
            if a.sensitivity == Sensitivity::Public {
                continue;
            }
            edits.push((a.value_span, REDACTED.to_string()));
        }
        for f in &self.inline_credentials {
            let replacement = if f.kind == "url" {
                redact_url_credentials(&f.value)
            } else {
                REDACTED.to_string()
            };
            edits.push((f.value_span, replacement));
        }
        apply_edits(&self.cmd, edits)
    }

    /// Like [`Self::redacted`], but redacts only assignments classified as
    /// [`Sensitivity::Secret`] (plus secret flags and URL credentials),
    /// leaving `Unknown` assignments intact so echoed output matches what
    /// `init` persists to `config.toml`.
    pub fn redact_secrets_only(&self) -> String {
        let mut edits: Vec<((usize, usize), String)> = Vec::new();
        for a in &self.assignments {
            if a.sensitivity != Sensitivity::Secret {
                continue;
            }
            edits.push((a.value_span, REDACTED.to_string()));
        }
        for f in &self.inline_credentials {
            let replacement = if f.kind == "url" {
                redact_url_credentials(&f.value)
            } else {
                REDACTED.to_string()
            };
            edits.push((f.value_span, replacement));
        }
        apply_edits(&self.cmd, edits)
    }

    /// The command with the given assignments removed (with the whitespace
    /// after them). An `export` left without arguments is removed together
    /// with the operator that follows it.
    pub fn without_assignments(&self, names: &[String]) -> String {
        let mut remove: Vec<(usize, usize)> = self
            .assignments
            .iter()
            .filter(|a| names.contains(&a.name))
            .map(|a| a.word)
            .collect();
        // `export A=x && cmd` -> `cmd` once A is removed.
        for (i, tok) in self.toks.iter().enumerate() {
            let Tok::Word { start, end, text } = tok else {
                continue;
            };
            if text != "export" {
                continue;
            }
            let mut args = Vec::new();
            let mut next_op = None;
            for t in &self.toks[i + 1..] {
                match t {
                    Tok::Word { start, end, .. } => args.push((*start, *end)),
                    Tok::Op { start, end } => {
                        next_op = Some((*start, *end));
                        break;
                    }
                }
            }
            if !args.is_empty() && args.iter().all(|w| remove.contains(w)) {
                remove.push((*start, *end));
                if let Some(op) = next_op {
                    remove.push(op);
                }
            }
        }
        let edits = remove
            .into_iter()
            .map(|(s, e)| {
                // Swallow the whitespace after the removed token.
                let tail = self.cmd[e..]
                    .bytes()
                    .take_while(|b| *b == b' ' || *b == b'\t')
                    .count();
                ((s, e + tail), String::new())
            })
            .collect();
        apply_edits(&self.cmd, edits).trim().to_string()
    }
}

/// Apply non-overlapping span replacements.
fn apply_edits(cmd: &str, mut edits: Vec<((usize, usize), String)>) -> String {
    edits.sort_by_key(|((s, _), _)| *s);
    let mut out = String::with_capacity(cmd.len());
    let mut pos = 0;
    for ((s, e), replacement) in edits {
        if s < pos {
            continue;
        }
        out.push_str(&cmd[pos..s]);
        out.push_str(&replacement);
        pos = e;
    }
    out.push_str(&cmd[pos..]);
    out
}

/// A command safe to print: assignment values and credentials redacted.
pub fn redact_command(cmd: &str) -> String {
    scan(cmd).redacted()
}

/// A dev command with its secrets moved out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Externalized {
    /// The command without the moved assignments.
    pub command: String,
    /// Variables moved to `dev_env` as `env:NAME` references.
    pub moved: Vec<String>,
}

/// Move secret inline assignments out of `cmd`. Each secret `NAME=value`
/// is removed and recorded as an `env:NAME` reference when `lookup(NAME)`
/// (the caller's environment) has the same value. Otherwise, and for secret
/// flags and credential URLs that cannot be moved automatically, returns an
/// error message (it never contains a secret value) explaining how to pass
/// the values instead.
pub fn externalize(
    cmd: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> std::result::Result<Externalized, String> {
    let scan = scan(cmd);
    let mut moved = Vec::new();
    let mut missing = Vec::new();
    let mut differs = Vec::new();
    for a in scan.secret_assignments() {
        match lookup(&a.name) {
            Some(v) if v == a.value => moved.push(a.name.clone()),
            Some(_) => differs.push(a.name.clone()),
            None => missing.push(a.name.clone()),
        }
    }
    if missing.is_empty() && differs.is_empty() && scan.inline_credentials.is_empty() {
        let command = scan.without_assignments(&moved);
        if !moved.is_empty() && command.is_empty() {
            return Err(
                "the dev command is empty once its secret assignments are removed; pass the command that starts the server".to_string(),
            );
        }
        return Ok(Externalized { command, moved });
    }

    let all: Vec<String> = scan.secret_assignments().map(|a| a.name.clone()).collect();
    let remaining = scan.without_assignments(&all);
    let mut msg = String::from(
        "--dev-cmd contains secret values; `brokenapp init` never writes secrets to .brokenapp/config.toml.\n",
    );
    if !missing.is_empty() {
        let _ = writeln!(msg, "  not set in this shell: {}", missing.join(", "));
    }
    if !differs.is_empty() {
        let _ = writeln!(
            msg,
            "  set in this shell to a different value: {} (init will not guess which one `map` should use)",
            differs.join(", ")
        );
    }
    for f in &scan.inline_credentials {
        let what = if f.kind == "url" {
            "a URL with credentials".to_string()
        } else {
            format!("secret flag {}", f.name)
        };
        let _ = writeln!(
            msg,
            "  {what}: read it from an environment variable in your dev script instead of passing it on the command line"
        );
    }
    let pending: Vec<&String> = missing.iter().chain(differs.iter()).collect();
    if !pending.is_empty() {
        msg.push_str("Export them in the shell that runs brokenapp, then re-run init:\n");
        for name in &pending {
            let _ = writeln!(msg, "  export {name}=...");
        }
        let _ = writeln!(
            msg,
            "  brokenapp init --dev-cmd {} ...",
            shell_words::quote(&scan_for_display(&remaining))
        );
        msg.push_str(
            "init then records them in config.toml as references, e.g. [project.dev_env] ",
        );
        let first = pending[0];
        let _ = write!(msg, "{first} = \"env:{first}\"");
        msg.push_str(
            ", and `map` reads the values from the environment when it starts the dev server.",
        );
    }
    Err(msg.trim_end().to_string())
}

fn scan_for_display(cmd: &str) -> String {
    redact_command(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn classifies_secret_and_public_names() {
        use Sensitivity::*;
        assert_eq!(
            classify("DATABASE_URL", "postgresql://app@localhost/db"),
            Secret
        );
        assert_eq!(classify("DATABASE_URL", "postgres://u:p@db/x"), Secret);
        assert_eq!(classify("OPENAI_API_KEY", "sk-abc"), Secret);
        assert_eq!(classify("STRIPE_SECRET", "abc"), Secret);
        assert_eq!(classify("GITHUBTOKEN", "abc"), Secret);
        assert_eq!(classify("ADMIN_PASSWORD", "hunter2"), Secret);
        assert_eq!(classify("SESSION_KEY", "abc"), Secret);
        assert_eq!(classify("REDIS_URL", "redis://localhost:6379"), Secret);
        assert_eq!(
            classify("SENTRY_DSN", "https://k@o1.ingest.sentry.io/1"),
            Secret
        );
        assert_eq!(classify("ANY_NAME", "https://user:pw@host/x"), Secret);
        assert_eq!(classify("ANY_NAME", "ghp_0123456789"), Secret);

        assert_eq!(classify("PORT", "3000"), Public);
        assert_eq!(classify("NODE_ENV", "development"), Public);
        assert_eq!(classify("X_ENABLED", "false"), Public);
        assert_eq!(classify("NEXT_TELEMETRY_DISABLED", "1"), Public);
        assert_eq!(classify("ASTRO_TELEMETRY_DISABLED", "1"), Public);
        assert_eq!(
            classify("OPENAI_API_KEY", ""),
            Public,
            "empty disables, leaks nothing"
        );
        assert_eq!(classify("PWD", "/tmp"), Unknown);
        assert_eq!(classify("MONKEY_COUNT", "3"), Public);
        assert_eq!(classify("APP_URL", "http://127.0.0.1:3000"), Unknown);
        assert_eq!(classify("SSL_KEY_FILE", "./certs/key.pem"), Unknown);
        assert_eq!(classify("REGION", "ASIA"), Unknown);
        assert_eq!(classify("AWS_ID", "AKIAABCDEFGHIJKLMNOP"), Secret);
    }

    #[test]
    fn finds_assignments_in_command_position_only() {
        let s =
            scan("DATABASE_URL=postgres://u:pw@localhost/db PORT=3000 npm run dev -- --flag=X=1");
        let names: Vec<&str> = s.assignments.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec!["DATABASE_URL", "PORT"]);
        assert_eq!(s.secret_names(), vec!["DATABASE_URL"]);

        let s = scan("cd web && env -i API_TOKEN='a b' cross-env HOST=0 next dev; X=1 vite");
        let names: Vec<&str> = s.assignments.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec!["API_TOKEN", "HOST", "X"]);
        assert_eq!(s.assignments[0].value(), "a b");
        // After the command word, `NAME=value` is an argument.
        let s = scan("next dev SECRET_KEY=x");
        assert!(s.assignments.is_empty());
        let s = scan("cross-env HOST=0 SECRET_KEY=\"x\\\"y\" next dev");
        let names: Vec<&str> = s.assignments.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec!["HOST", "SECRET_KEY"]);
        assert_eq!(s.assignments[1].value(), "x\"y");
    }

    #[test]
    fn redacts_values_but_keeps_public_ones() {
        let cmd = "DATABASE_URL=postgres://u:pw@localhost/db OPENAI_API_KEY='' APP_URL=http://127.0.0.1:3000 PORT=3000 node_modules/.bin/next dev --port $PORT";
        let shown = redact_command(cmd);
        assert_eq!(
            shown,
            "DATABASE_URL=*** OPENAI_API_KEY='' APP_URL=*** PORT=3000 node_modules/.bin/next dev --port $PORT"
        );
        assert!(!shown.contains("pw"));
        assert_eq!(
            redact_command(
                "node server.js --db postgres://u:pw@localhost/x --api-key abc --token=xyz"
            ),
            "node server.js --db postgres://u:***@localhost/x --api-key *** --token=***"
        );
        assert_eq!(redact_command("npm run dev"), "npm run dev");
        // Certificate paths are locations, not secrets.
        let s = scan("next dev --experimental-https-key ./certs/key.pem");
        assert!(!s.has_secrets());
    }

    #[test]
    fn removal_keeps_the_rest_byte_for_byte() {
        let s = scan("DATABASE_URL=\"postgres://u:p@h/db\"  PORT=3100 next dev -p $PORT 'a  b'");
        assert_eq!(
            s.without_assignments(&["DATABASE_URL".into()]),
            "PORT=3100 next dev -p $PORT 'a  b'"
        );
        let s = scan("export API_TOKEN=abc && npm run dev");
        assert_eq!(s.without_assignments(&["API_TOKEN".into()]), "npm run dev");
        let s = scan("export API_TOKEN=abc PORT=1 && npm run dev");
        assert_eq!(
            s.without_assignments(&["API_TOKEN".into()]),
            "export PORT=1 && npm run dev"
        );
        let s = scan("cd web && STRIPE_SECRET=x npm run dev");
        assert_eq!(
            s.without_assignments(&["STRIPE_SECRET".into()]),
            "cd web && npm run dev"
        );
    }

    #[test]
    fn externalize_moves_exported_secrets() {
        let cmd = "DATABASE_URL=postgres://u:pw@localhost/db NEXT_TELEMETRY_DISABLED=1 X_ENABLED=false next dev --port 3000";
        let out = externalize(
            cmd,
            env_of(&[("DATABASE_URL", "postgres://u:pw@localhost/db")]),
        )
        .unwrap();
        assert_eq!(
            out.command,
            "NEXT_TELEMETRY_DISABLED=1 X_ENABLED=false next dev --port 3000"
        );
        assert_eq!(out.moved, vec!["DATABASE_URL"]);

        let plain = externalize("npm run dev", env_of(&[])).unwrap();
        assert_eq!(plain.command, "npm run dev");
        assert!(plain.moved.is_empty());
    }

    #[test]
    fn externalize_refuses_without_leaking_values() {
        let cmd = "DATABASE_URL=postgres://u:hunter2@localhost/db API_KEY=sk-live-123 npm run dev";
        let err = externalize(cmd, env_of(&[("API_KEY", "a-different-value")])).unwrap_err();
        assert!(err.contains("not set in this shell: DATABASE_URL"), "{err}");
        assert!(err.contains("different value: API_KEY"), "{err}");
        assert!(err.contains("export DATABASE_URL=..."), "{err}");
        assert!(
            err.contains("brokenapp init --dev-cmd 'npm run dev'"),
            "{err}"
        );
        assert!(err.contains("DATABASE_URL = \"env:DATABASE_URL\""), "{err}");
        assert!(
            !err.contains("hunter2") && !err.contains("sk-live"),
            "{err}"
        );

        let err = externalize("node server.js --db postgres://u:pw@h/x", env_of(&[])).unwrap_err();
        assert!(err.contains("URL with credentials"), "{err}");
        assert!(!err.contains("pw@"), "{err}");

        let err = externalize("API_KEY=k", env_of(&[("API_KEY", "k")])).unwrap_err();
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn dev_command_moves_only_the_database_url() {
        // Representative dev command: one real secret alongside empty or public
        // switches.
        let cmd = "env NEXT_TELEMETRY_DISABLED=1 APP_URL=http://127.0.0.1:47301 DATABASE_URL=postgresql://devuser@localhost:5432/app_dev_db OPENAI_API_KEY='' FEATURE_ENABLED=false X_BRIDGE_API_KEY='' AUTH_APP_SECRET='' node_modules/.bin/next dev --hostname 127.0.0.1 --port 47301";
        let s = scan(cmd);
        assert_eq!(s.secret_names(), vec!["DATABASE_URL"]);
        let out = externalize(
            cmd,
            env_of(&[(
                "DATABASE_URL",
                "postgresql://devuser@localhost:5432/app_dev_db",
            )]),
        )
        .unwrap();
        assert_eq!(out.moved, vec!["DATABASE_URL"]);
        assert!(!out.command.contains("DATABASE_URL"));
        assert!(
            out.command
                .starts_with("env NEXT_TELEMETRY_DISABLED=1 APP_URL=")
        );
        assert!(
            out.command
                .ends_with("next dev --hostname 127.0.0.1 --port 47301")
        );
        let shown = redact_command(cmd);
        assert!(shown.contains("DATABASE_URL=*** "), "{shown}");
        assert!(shown.contains("OPENAI_API_KEY='' "), "{shown}");
        assert!(!shown.contains("devuser@"), "{shown}");
    }

    #[test]
    fn url_credentials_are_redacted() {
        assert_eq!(
            redact_url_credentials("postgres://app:pw@localhost:5432/db"),
            "postgres://app:***@localhost:5432/db"
        );
        assert_eq!(
            redact_url_credentials("http://localhost:3000/a@b"),
            "http://localhost:3000/a@b"
        );
        assert!(!url_has_userinfo("http://localhost:3000/?u=a@b"));
        assert!(url_has_userinfo("postgresql://devuser@localhost:5432/x"));
    }

    #[test]
    fn path_qualified_env_prefixes_catch_and_externalize_secrets() {
        const JWT: &str =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.signature123";
        let cmd = format!("/usr/bin/env 'SUPABASE_SERVICE_ROLE_KEY={JWT}' npm run dev");

        let scanned = scan(&cmd);
        assert!(scanned.has_secrets());
        assert_eq!(scanned.secret_names(), vec!["SUPABASE_SERVICE_ROLE_KEY"]);

        let shown = redact_command(&cmd);
        assert_eq!(
            shown,
            "/usr/bin/env 'SUPABASE_SERVICE_ROLE_KEY=***' npm run dev"
        );
        assert!(!shown.contains("eyJhbG"));

        // Unexported: refused without leaking the JWT.
        let err = externalize(&cmd, env_of(&[])).unwrap_err();
        assert!(err.contains("SUPABASE_SERVICE_ROLE_KEY"), "{err}");
        assert!(!err.contains("eyJhbG"), "{err}");

        // Exported: moved out of the command into dev_env.
        let out = externalize(&cmd, env_of(&[("SUPABASE_SERVICE_ROLE_KEY", JWT)])).unwrap();
        assert_eq!(out.moved, vec!["SUPABASE_SERVICE_ROLE_KEY"]);
        assert_eq!(out.command, "/usr/bin/env npm run dev");

        // Path-qualified cross-env is also recognized.
        let cross = scan("./node_modules/.bin/cross-env API_KEY=sk-live-abc123 next dev");
        assert_eq!(cross.secret_names(), vec!["API_KEY"]);

        // redact_secrets_only leaves Unknown assignments intact while redacting Secret ones.
        let mixed = scan(
            "NEXT_PUBLIC_API_URL=https://api.example.com/api API_KEY=sk-live-abc123 npm run dev",
        );
        assert_eq!(
            mixed.redact_secrets_only(),
            "NEXT_PUBLIC_API_URL=https://api.example.com/api API_KEY=*** npm run dev"
        );
    }
}
