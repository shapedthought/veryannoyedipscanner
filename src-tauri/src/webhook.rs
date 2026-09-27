//! Telling something else what changed.
//!
//! One POST of JSON to a URL you configure. The payload carries the same
//! shape as the Changes tab, plus `text` and `content` fields so Slack and
//! Discord webhooks render something readable without any mapping.

use serde_json::Value;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(10);

/// Refuse anything that isn't a plain http(s) URL, so a typo can't turn into
/// a file read or a request to a local socket.
fn check_url(url: &str) -> Result<reqwest::Url, String> {
    let parsed = reqwest::Url::parse(url.trim())
        .map_err(|e| format!("That isn't a URL I can post to: {e}"))?;
    match parsed.scheme() {
        "http" | "https" => Ok(parsed),
        other => Err(format!("I can post to http or https, not {other}.")),
    }
}

/// POST the payload. Returns the status line, so the UI can say what happened.
pub async fn post(url: &str, payload: &Value) -> Result<String, String> {
    let url = check_url(url)?;
    let client = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .user_agent("VeryAnnoyedIPScanner/0.2")
        .build()
        .map_err(|e| format!("Couldn't start an HTTP client: {e}"))?;

    let response = client
        .post(url)
        .json(payload)
        .send()
        .await
        .map_err(|e| format!("Couldn't reach it: {e}"))?;

    let status = response.status();
    if status.is_success() {
        return Ok(status.to_string());
    }
    // The body usually says why; Slack in particular is terse but clear.
    let body = response.text().await.unwrap_or_default();
    let reason = body.trim().chars().take(200).collect::<String>();
    Err(if reason.is_empty() {
        format!("It answered {status}.")
    } else {
        format!("It answered {status}: {reason}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_http_urls_are_accepted() {
        assert!(check_url("https://hooks.example.com/abc").is_ok());
        assert!(check_url("  http://10.0.0.5:8123/api/webhook/x  ").is_ok());
        assert!(check_url("file:///etc/passwd").is_err());
        assert!(check_url("ftp://example.com").is_err());
        assert!(check_url("not a url").is_err());
        assert!(check_url("").is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reports_what_the_far_end_said() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            // One success, then one refusal.
            for reply in [
                "HTTP/1.1 204 No Content\r\n\r\n",
                "HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\ninvalid_url",
            ] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 2048];
                let _ = socket.read(&mut buf).await;
                let _ = socket.write_all(reply.as_bytes()).await;
                let _ = socket.flush().await;
            }
        });

        let url = format!("http://127.0.0.1:{port}/hook");
        let payload = serde_json::json!({ "text": "1 new device" });
        assert!(post(&url, &payload).await.unwrap().contains("204"));

        let refused = post(&url, &payload).await.unwrap_err();
        assert!(refused.contains("400"), "{refused}");
        assert!(
            refused.contains("invalid_url"),
            "the body explains why: {refused}"
        );
    }
}
