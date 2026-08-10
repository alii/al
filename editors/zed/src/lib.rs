use zed_extension_api::{self as zed, settings::LspSettings, LanguageServerId, Result};

struct ScarletExtension;

impl zed::Extension for ScarletExtension {
    fn new() -> Self {
        Self
    }

    fn language_server_command(
        &mut self,
        language_server_id: &LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<zed::Command> {
        let binary_settings = LspSettings::for_worktree(language_server_id.as_ref(), worktree)
            .ok()
            .and_then(|settings| settings.binary);

        let command = binary_settings
            .as_ref()
            .and_then(|binary| binary.path.clone())
            .or_else(|| worktree.which("scarlet"))
            .ok_or_else(|| {
                "scarlet binary not found on PATH; install it or set its location \
                 via the `lsp.scarlet.binary.path` setting"
                    .to_string()
            })?;

        let args = binary_settings
            .and_then(|binary| binary.arguments)
            .unwrap_or_else(|| vec!["lsp".to_string()]);

        Ok(zed::Command {
            command,
            args,
            env: Vec::new(),
        })
    }
}

zed::register_extension!(ScarletExtension);
