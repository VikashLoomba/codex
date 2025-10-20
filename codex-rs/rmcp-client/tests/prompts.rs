use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use codex_rmcp_client::RmcpClient;
use escargot::CargoBuild;
use mcp_types::ClientCapabilities;
use mcp_types::ContentBlock;
use mcp_types::GetPromptRequestParams;
use mcp_types::GetPromptResult;
use mcp_types::Implementation;
use mcp_types::InitializeRequestParams;
use mcp_types::ListPromptsResult;
use mcp_types::Prompt;
use mcp_types::PromptArgument;
use mcp_types::PromptMessage;
use mcp_types::Role;
use mcp_types::TextContent;
use pretty_assertions::assert_eq;
use serde_json::json;

const PROMPT_NAME: &str = "greet-user";

fn stdio_server_bin() -> anyhow::Result<PathBuf> {
    let build = CargoBuild::new()
        .package("codex-rmcp-client")
        .bin("test_stdio_server")
        .run()?;
    Ok(build.path().to_path_buf())
}

fn init_params() -> InitializeRequestParams {
    InitializeRequestParams {
        capabilities: ClientCapabilities {
            experimental: None,
            roots: None,
            sampling: None,
            elicitation: Some(json!({})),
        },
        client_info: Implementation {
            name: "codex-test".into(),
            version: "0.0.0-test".into(),
            title: Some("Codex rmcp prompt test".into()),
            user_agent: None,
        },
        protocol_version: mcp_types::MCP_SCHEMA_VERSION.to_string(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn rmcp_client_can_list_prompts() -> anyhow::Result<()> {
    let client = RmcpClient::new_stdio_client(
        stdio_server_bin()?.into(),
        Vec::<OsString>::new(),
        None,
        &[],
        None,
    )
    .await?;

    client
        .initialize(init_params(), Some(Duration::from_secs(5)))
        .await?;

    let list = client
        .list_prompts(None, Some(Duration::from_secs(5)))
        .await?;
    assert_eq!(
        list,
        ListPromptsResult {
            next_cursor: None,
            prompts: vec![Prompt {
                arguments: Some(vec![PromptArgument {
                    description: Some("Name to greet".to_string()),
                    name: "name".to_string(),
                    required: Some(true),
                    title: Some("Recipient".to_string()),
                }]),
                description: Some("Send a friendly greeting to the provided user.".to_string()),
                name: PROMPT_NAME.to_string(),
                title: Some("Greet User".to_string()),
            }],
        }
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn rmcp_client_lists_prompt_argument_metadata() -> anyhow::Result<()> {
    let client = RmcpClient::new_stdio_client(
        stdio_server_bin()?.into(),
        Vec::<OsString>::new(),
        None,
        &[],
        None,
    )
    .await?;

    client
        .initialize(init_params(), Some(Duration::from_secs(5)))
        .await?;

    let list = client
        .list_prompts(None, Some(Duration::from_secs(5)))
        .await?;
    let prompt = list
        .prompts
        .iter()
        .find(|prompt| prompt.name == PROMPT_NAME)
        .expect("prompt missing from list");

    let argument = prompt
        .arguments
        .as_ref()
        .and_then(|args| args.first())
        .expect("prompt missing argument metadata");

    assert_eq!(argument.name, "name");
    assert_eq!(argument.description.as_deref(), Some("Name to greet"));
    assert_eq!(argument.required, Some(true));
    assert_eq!(argument.title.as_deref(), Some("Recipient"));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn rmcp_client_reports_unknown_prompt_error() -> anyhow::Result<()> {
    let client = RmcpClient::new_stdio_client(
        stdio_server_bin()?.into(),
        Vec::<OsString>::new(),
        None,
        &[],
        None,
    )
    .await?;

    client
        .initialize(init_params(), Some(Duration::from_secs(5)))
        .await?;

    let err = client
        .get_prompt(
            GetPromptRequestParams {
                name: "non-existent".to_string(),
                arguments: None,
            },
            Some(Duration::from_secs(5)),
        )
        .await
        .expect_err("expected prompts/get to fail for unknown prompt");

    assert!(
        err.to_string().contains("prompt `non-existent` not found"),
        "unexpected error: {err:#}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn rmcp_client_can_get_prompt() -> anyhow::Result<()> {
    let client = RmcpClient::new_stdio_client(
        stdio_server_bin()?.into(),
        Vec::<OsString>::new(),
        None,
        &[],
        None,
    )
    .await?;

    client
        .initialize(init_params(), Some(Duration::from_secs(5)))
        .await?;

    let prompt = client
        .get_prompt(
            GetPromptRequestParams {
                name: PROMPT_NAME.to_string(),
                arguments: Some(json!({ "name": "Codex" })),
            },
            Some(Duration::from_secs(5)),
        )
        .await?;

    assert_eq!(
        prompt,
        GetPromptResult {
            description: Some("Send a friendly greeting to the provided user.".to_string()),
            messages: vec![PromptMessage {
                content: ContentBlock::TextContent(TextContent {
                    annotations: None,
                    text: "Hello, Codex!".to_string(),
                    r#type: "text".to_string(),
                }),
                role: Role::Assistant,
            }],
        }
    );

    Ok(())
}
