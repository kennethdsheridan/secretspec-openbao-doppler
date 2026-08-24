//! Doppler provider backed by the `doppler` CLI (0.20+).
//!
//! The URI selects one Doppler project and config. Convention addresses and
//! native `ref` addresses both name a flat Doppler secret key; the SecretSpec
//! project and profile therefore do not affect the key stored by Doppler.

use super::{
    Address, DiscoveryContext, Provider, ProviderCredentials, ProviderUrl, credential_or_env,
    flat_item,
};
use crate::config::NativeAddress;
use crate::{Result, Secret, SecretSpecError};
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::io::{self, Write};
use std::process::{Command, Output, Stdio};

const CLI_PATH_ENV: &str = "SECRETSPEC_DOPPLER_CLI_PATH";
const ACCESS_TOKEN: &str = "access_token";
const DOPPLER_TOKEN_ENV: &str = "DOPPLER_TOKEN";

/// Configuration for one Doppler project and config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DopplerConfig {
    project: String,
    config: String,
}

impl TryFrom<&ProviderUrl> for DopplerConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> Result<Self> {
        if url.scheme() != "doppler" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for doppler provider; expected 'doppler'",
                url.scheme()
            )));
        }
        if !url.username().is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "doppler:// takes the project name as its authority, not a username".to_string(),
            ));
        }
        if url.query_pairs().next().is_some() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "doppler:// does not accept query parameters; use doppler://PROJECT/CONFIG"
                    .to_string(),
            ));
        }
        if url.port().is_some() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "doppler:// does not accept a port; use doppler://PROJECT/CONFIG".to_string(),
            ));
        }
        if url.fragment().is_some() {
            return Err(SecretSpecError::ProviderOperationFailed(
                "doppler:// does not accept a fragment; use doppler://PROJECT/CONFIG".to_string(),
            ));
        }

        let project = url
            .host()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(
                    "Doppler project is required; use doppler://PROJECT/CONFIG".to_string(),
                )
            })?;
        let config = url.path().trim_matches('/').to_string();
        if config.is_empty() || config.contains('/') {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Doppler config is required and must be one path component; use doppler://PROJECT/CONFIG"
                    .to_string(),
            ));
        }

        Ok(Self { project, config })
    }
}

/// A provider for Doppler secrets in one project/config namespace.
pub struct DopplerProvider {
    config: DopplerConfig,
    credentials: ProviderCredentials,
    cli_binary_path: String,
}

crate::register_provider! {
    struct: DopplerProvider,
    config: DopplerConfig,
    name: "doppler",
    description: "Doppler secrets manager via the Doppler CLI (0.20+)",
    schemes: ["doppler"],
    examples: ["doppler://project/config", "doppler://my-app/dev"],
    credential_names: [ACCESS_TOKEN],
}

impl DopplerProvider {
    pub fn new(config: DopplerConfig) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
            cli_binary_path: std::env::var(CLI_PATH_ENV).unwrap_or_else(|_| "doppler".to_string()),
        }
    }

    fn access_token(&self) -> Option<String> {
        credential_or_env(&self.credentials, ACCESS_TOKEN, DOPPLER_TOKEN_ENV)
    }

    fn command(&self) -> Command {
        self.command_with_access_token(self.access_token())
    }

    fn command_with_access_token(&self, token: Option<String>) -> Command {
        let mut command = Command::new(&self.cli_binary_path);
        // Select authentication once so a provider credential reliably overrides
        // the parent environment and the CLI cannot resolve another token.
        command.env_remove(DOPPLER_TOKEN_ENV);
        if let Some(token) = token {
            command.env(DOPPLER_TOKEN_ENV, token);
        }
        command
    }

    fn spawn_error(&self, error: io::Error) -> SecretSpecError {
        if error.kind() == io::ErrorKind::NotFound {
            SecretSpecError::ProviderOperationFailed(format!(
                "Doppler CLI executable '{}' was not found; install it from https://docs.doppler.com/docs/cli or set {CLI_PATH_ENV}",
                self.cli_binary_path
            ))
        } else {
            SecretSpecError::ProviderOperationFailed(format!(
                "failed to execute Doppler CLI '{}': {error}",
                self.cli_binary_path
            ))
        }
    }

    fn redact(&self, message: &str, additional_secrets: &[&str]) -> String {
        let mut redacted = message.to_string();
        if let Some(token) = self.access_token().filter(|token| !token.is_empty()) {
            redacted = redacted.replace(&token, "[REDACTED]");
        }
        for secret in additional_secrets
            .iter()
            .filter(|secret| !secret.is_empty())
        {
            redacted = redacted.replace(secret, "[REDACTED]");
        }
        redacted
    }

    fn finish(&self, output: Output, additional_secrets: &[&str]) -> Result<String> {
        if output.status.success() {
            return String::from_utf8(output.stdout).map_err(|error| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Doppler CLI returned non-UTF-8 output: {}",
                    crate::error::display_error_chain(&error)
                ))
            });
        }

        let detail = self.redact(
            String::from_utf8_lossy(&output.stderr).trim(),
            additional_secrets,
        );
        let lower = detail.to_ascii_lowercase();
        if lower.contains("not logged in")
            || lower.contains("authentication")
            || lower.contains("invalid token")
        {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Doppler authentication is required; run `doppler login` or set DOPPLER_TOKEN"
                    .to_string(),
            ));
        }
        Err(SecretSpecError::ProviderOperationFailed(format!(
            "Doppler CLI failed for project '{}' config '{}': {}",
            self.config.project,
            self.config.config,
            if detail.is_empty() {
                "command exited unsuccessfully"
            } else {
                &detail
            }
        )))
    }

    fn run(&self, args: &[&str]) -> Result<String> {
        let output = self
            .command()
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|error| self.spawn_error(error))?;
        self.finish(output, &[])
    }

    fn secret_name<'a>(&self, addr: Address<'a>) -> Result<std::borrow::Cow<'a, str>> {
        let name = flat_item(self, addr)?;
        if name.is_empty() || name.contains('\0') {
            return Err(SecretSpecError::ProviderOperationFailed(
                "Doppler secret names must be non-empty and cannot contain NUL".to_string(),
            ));
        }
        Ok(name)
    }

    fn is_missing_secret(message: &str) -> bool {
        let message = message.to_ascii_lowercase();
        message.contains("could not find requested secret")
            || message.contains("secret not found")
            || message.contains("secret does not exist")
    }

    fn download_all(&self) -> Result<HashMap<String, String>> {
        let args = [
            "secrets",
            "download",
            "--format",
            "json",
            "--no-file",
            "--project",
            &self.config.project,
            "--config",
            &self.config.config,
        ];
        let output = self.run(&args)?;
        let secrets =
            serde_json::from_str::<HashMap<String, String>>(&output).map_err(|error| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Doppler CLI returned invalid secrets JSON: {error}"
                ))
            })?;
        Ok(secrets
            .into_iter()
            .filter(|(name, _)| !name.starts_with("DOPPLER_"))
            .collect())
    }
}

impl Provider for DopplerProvider {
    fn convention_address(
        &self,
        _project: &str,
        _profile: &str,
        key: &str,
    ) -> Result<NativeAddress> {
        Ok(NativeAddress {
            item: key.to_string(),
            ..Default::default()
        })
    }

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.credentials = credentials;
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        format!(
            "doppler://{}/{}",
            ProviderUrl::encode(&self.config.project),
            ProviderUrl::encode(&self.config.config)
        )
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        let name = self.secret_name(addr)?;
        let args = [
            "secrets",
            "get",
            name.as_ref(),
            "--plain",
            "--project",
            &self.config.project,
            "--config",
            &self.config.config,
        ];
        match self.run(&args) {
            Ok(value) => {
                // `doppler secrets get --plain` writes one delimiter newline.
                // Strip only that CLI framing byte; any whitespace belonging to
                // the secret, including a preceding trailing newline, is kept.
                let value = value.strip_suffix('\n').unwrap_or(&value);
                Ok(Some(SecretString::new(value.to_owned().into())))
            }
            Err(SecretSpecError::ProviderOperationFailed(message))
                if Self::is_missing_secret(&message) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        self.secret_name(addr).map(|_| ())
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        self.check_writable(addr)?;
        let name = self.secret_name(addr)?;
        let args = [
            "secrets",
            "set",
            name.as_ref(),
            "--project",
            &self.config.project,
            "--config",
            &self.config.config,
        ];
        let mut command = self.command();
        command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|error| self.spawn_error(error))?;
        let mut stdin = match child.stdin.take() {
            Some(stdin) => stdin,
            None => {
                let output = child
                    .wait_with_output()
                    .map_err(|error| self.spawn_error(error))?;
                let detail = self
                    .finish(output, &[value.expose_secret()])
                    .err()
                    .map_or_else(
                        || "Doppler CLI exited successfully".to_string(),
                        |error| error.to_string(),
                    );
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "failed to open Doppler CLI stdin for the secret value; {detail}"
                )));
            }
        };
        let write_error = stdin.write_all(value.expose_secret().as_bytes()).err();
        drop(stdin);
        let output = child
            .wait_with_output()
            .map_err(|error| self.spawn_error(error))?;
        if let Some(error) = write_error {
            let detail = self
                .finish(output, &[value.expose_secret()])
                .err()
                .map_or_else(
                    || "Doppler CLI exited successfully".to_string(),
                    |error| error.to_string(),
                );
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "failed to write secret value to Doppler CLI stdin: {error}; {detail}"
            )));
        }
        self.finish(output, &[value.expose_secret()]).map(|_| ())
    }

    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretString>> {
        let requested = requests
            .iter()
            .map(|(logical_name, addr)| Ok((*logical_name, self.secret_name(*addr)?.into_owned())))
            .collect::<Result<Vec<_>>>()?;
        Ok(self
            .download_all()?
            .into_iter()
            .flat_map(|(name, value)| {
                requested
                    .iter()
                    .filter(move |(_, native_name)| native_name == &name)
                    .map(move |(logical_name, _)| {
                        (
                            (*logical_name).to_string(),
                            SecretString::new(value.clone().into()),
                        )
                    })
            })
            .collect())
    }

    fn reflect(&self, _context: DiscoveryContext<'_>) -> Result<HashMap<String, Secret>> {
        Ok(self
            .download_all()?
            .into_keys()
            .map(|name| {
                let secret = Secret::required(format!("{name} Doppler secret"));
                (name, secret)
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider_url(spec: &str) -> ProviderUrl {
        ProviderUrl::new(url::Url::parse(spec).unwrap())
    }

    fn config(spec: &str) -> DopplerConfig {
        DopplerConfig::try_from(&provider_url(spec)).unwrap()
    }

    #[test]
    fn parses_and_round_trips_a_project_and_config() {
        let provider = DopplerProvider::new(config("doppler://my-app/dev"));
        assert_eq!(provider.uri(), "doppler://my-app/dev");
        assert_eq!(config(&provider.uri()), provider.config);
    }

    #[test]
    fn rejects_invalid_doppler_uris() {
        for spec in [
            "doppler://",
            "doppler://project",
            "doppler://project/dev/nested",
            "doppler://user@project/dev",
            "doppler://project/dev?unexpected=value",
            "doppler://project:443/dev",
            "doppler://project/dev#fragment",
        ] {
            assert!(
                DopplerConfig::try_from(&provider_url(spec)).is_err(),
                "{spec}"
            );
        }
    }

    #[test]
    fn convention_and_native_references_are_flat_secret_names() {
        let provider = DopplerProvider::new(config("doppler://project/dev"));
        assert_eq!(
            provider
                .convention_address("ignored-project", "ignored-profile", "DATABASE_URL")
                .unwrap()
                .item,
            "DATABASE_URL"
        );
        let reference = NativeAddress {
            item: "EXISTING_KEY".to_string(),
            ..Default::default()
        };
        assert_eq!(
            provider.secret_name(Address::Native(&reference)).unwrap(),
            "EXISTING_KEY"
        );
    }

    #[test]
    fn registration_declares_the_access_token_credential() {
        let registration = crate::provider::PROVIDER_REGISTRY
            .iter()
            .find(|registration| registration.info.name == "doppler")
            .unwrap();
        assert_eq!(registration.credential_names, &[ACCESS_TOKEN]);
    }

    #[test]
    fn selected_access_token_overrides_and_scrubs_the_parent_environment() {
        let _lock = crate::tests::scrub_resolution_env();
        let _token = crate::tests::EnvVarGuard::set(DOPPLER_TOKEN_ENV, "from-environment");
        let mut provider = DopplerProvider::new(config("doppler://project/dev"));
        let mut credentials = ProviderCredentials::new();
        credentials.insert(
            ACCESS_TOKEN.to_string(),
            SecretString::new("from-credential".into()),
        );
        provider.with_credentials(credentials);

        let command = provider.command();
        let token = command
            .get_envs()
            .find(|(name, _)| *name == DOPPLER_TOKEN_ENV)
            .and_then(|(_, value)| value)
            .unwrap();
        assert_eq!(token, "from-credential");
        assert!(!provider.uri().contains("from-credential"));
    }

    #[test]
    fn command_without_a_selected_token_scrubs_doppler_token() {
        let provider = DopplerProvider::new(config("doppler://project/dev"));
        let command = provider.command_with_access_token(None);
        let inherited_token = command
            .get_envs()
            .find(|(name, _)| *name == DOPPLER_TOKEN_ENV)
            .unwrap_or_else(|| panic!("{DOPPLER_TOKEN_ENV} must be scrubbed"));
        assert!(inherited_token.1.is_none());
    }

    #[cfg(unix)]
    struct FakeDoppler {
        dir: tempfile::TempDir,
        provider: DopplerProvider,
    }

    #[cfg(unix)]
    impl FakeDoppler {
        fn new() -> Self {
            use std::os::unix::fs::PermissionsExt;

            let dir = tempfile::tempdir().unwrap();
            let binary = dir.path().join("doppler");
            let scratch = dir.path().join("doppler.script");
            std::fs::write(
                &scratch,
                r#"#!/bin/sh
fixture_dir=$(dirname "$0")
printf '%s\n' "$*" >> "$fixture_dir/invocations.log"
case "$1 $2" in
  "secrets get")
    if [ "$3" = "MISSING" ]; then
      printf 'could not find requested secret\n' >&2
      exit 1
    fi
    if [ "$3" = "WHITESPACE" ]; then
      printf ' leading and trailing  \n\n'
    elif [ "$3" = "EMPTY" ]; then
      :
    else
      printf 'secret-value\n'
    fi
    ;;
  "secrets download") printf '{"DATABASE_URL":"postgres://db","DOPPLER_PROJECT":"project"}' ;;
  "secrets set")
    if [ "$3" = "WRITE_FAILURE" ]; then
      exec 0<&-
      sleep 0.1
      printf 'rejected %s\n' "$DOPPLER_TOKEN" >&2
      head -c 1048576 /dev/zero | tr '\000' x >&2
      printf done > "$fixture_dir/reaped.log"
      exit 1
    fi
    cat > "$fixture_dir/stdin.log"
    ;;
  *) printf 'unexpected Doppler invocation: %s\n' "$*" >&2; exit 2 ;;
esac
"#,
            )
            .unwrap();
            std::fs::rename(&scratch, &binary).unwrap();
            let mut permissions = std::fs::metadata(&binary).unwrap().permissions();
            permissions.set_mode(0o700);
            std::fs::set_permissions(&binary, permissions).unwrap();

            let mut provider = DopplerProvider::new(config("doppler://project/dev"));
            provider.cli_binary_path = binary.to_string_lossy().into_owned();
            Self { dir, provider }
        }

        fn read(&self, name: &str) -> String {
            std::fs::read_to_string(self.dir.path().join(name)).unwrap_or_default()
        }
    }

    #[cfg(unix)]
    #[test]
    fn fake_cli_covers_get_missing_set_batch_and_discovery() {
        let fake = FakeDoppler::new();
        let address = Address::convention("app", "prod", "DATABASE_URL");
        assert_eq!(
            fake.provider.get(address).unwrap().unwrap().expose_secret(),
            "secret-value"
        );
        assert_eq!(
            fake.provider
                .get(Address::convention("app", "prod", "WHITESPACE"))
                .unwrap()
                .unwrap()
                .expose_secret(),
            " leading and trailing  \n"
        );
        assert_eq!(
            fake.provider
                .get(Address::convention("app", "prod", "EMPTY"))
                .unwrap()
                .unwrap()
                .expose_secret(),
            ""
        );
        assert!(
            fake.provider
                .get(Address::convention("app", "prod", "MISSING"))
                .unwrap()
                .is_none()
        );

        let value = SecretString::new("value-kept-off-argv".into());
        fake.provider.set(address, &value).unwrap();
        assert_eq!(fake.read("stdin.log"), value.expose_secret());
        assert!(!fake.read("invocations.log").contains(value.expose_secret()));

        let found = fake
            .provider
            .get_many(&[("DATABASE_URL", address)])
            .unwrap();
        assert_eq!(found["DATABASE_URL"].expose_secret(), "postgres://db");
        let discovered = fake
            .provider
            .reflect(DiscoveryContext::new("app", "prod"))
            .unwrap();
        assert!(discovered.contains_key("DATABASE_URL"));
        assert!(!discovered.contains_key("DOPPLER_PROJECT"));
    }

    #[cfg(unix)]
    #[test]
    fn set_reaps_the_cli_and_redacts_diagnostics_after_a_stdin_write_failure() {
        let mut fake = FakeDoppler::new();
        let mut credentials = ProviderCredentials::new();
        credentials.insert(
            ACCESS_TOKEN.to_string(),
            SecretString::new("doppler-token-that-must-not-leak".into()),
        );
        fake.provider.with_credentials(credentials);
        let value = SecretString::new("x".repeat(1024 * 1024).into());

        let error = fake
            .provider
            .set(Address::convention("app", "prod", "WRITE_FAILURE"), &value)
            .unwrap_err()
            .to_string();

        assert!(error.contains("failed to write secret value"), "{error}");
        assert!(error.contains("[REDACTED]"), "{error}");
        assert!(
            !error.contains("doppler-token-that-must-not-leak"),
            "{error}"
        );
        assert!(!error.contains(value.expose_secret()), "{error}");
        assert_eq!(fake.read("reaped.log"), "done");
    }
}
