//! Upstream API compatibility shims.
//!
//! Translates incoming requests from common LLM API formats (OpenAI Chat
//! Completions, OpenAI Responses API, and Ollama chat) into the protocol's
//! internal [`CoreRequest`] shape, and reshapes the resulting [`CoreResponse`]
//! back into the format the caller expects. Each response also carries a
//! `zkapi` metadata block (charge applied, remaining balance, next anchor).
//! Also renders the model-listing endpoints (`/v1/models`, `/api/tags`).

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::config::ModelDescriptor;
use crate::service::{CoreRequest, CoreResponse};

// Lease keys have a small proof-bound dollar limit. Leaving a model's output
// unconstrained makes OpenRouter reserve headroom for its full model maximum,
// while a 1024-token fallback can exceed the $0.01 mainnet lease limit for
// otherwise valid requests. Keep the implicit ceiling conservative; callers
// that need longer answers can still provide an explicit completion limit.
const DIRECT_OPENROUTER_DEFAULT_MAX_TOKENS: u64 = 256;

pub fn core_request(path: &str, body: Value) -> CoreRequest {
    CoreRequest::post_json(path, body)
}

pub fn extract_model(body: &Value, fallback: &str) -> String {
    body.get("model")
        .and_then(Value::as_str)
        .unwrap_or(fallback)
        .to_string()
}

/// Normalize the local OpenAI/Responses/Ollama shims into an OpenRouter chat
/// completion. This transformation runs only on the user's machine; the zkAPI
/// server never receives the body.
pub fn openrouter_request(path: &str, body: Value) -> (String, Value) {
    const CHAT_PATH: &str = "/chat/completions";
    let object = body.as_object().cloned().unwrap_or_default();
    let messages = object.get("messages").cloned().or_else(|| {
        object.get("input").map(|input| match input {
            Value::String(text) => json!([{ "role": "user", "content": text }]),
            value => value.clone(),
        })
    });
    if path == "/v1/chat/completions" || path == CHAT_PATH {
        let mut object = object;
        ensure_direct_completion_limit(&mut object);
        object
            .entry("stream".to_string())
            .or_insert(Value::Bool(false));
        return (CHAT_PATH.to_string(), Value::Object(object));
    }

    let mut normalized = serde_json::Map::new();
    for key in [
        "model",
        "temperature",
        "max_tokens",
        "max_completion_tokens",
        "top_p",
        "stop",
        "tools",
        "tool_choice",
        "response_format",
        "stream",
    ] {
        if let Some(value) = object.get(key) {
            normalized.insert(key.to_string(), value.clone());
        }
    }
    if let Some(messages) = messages {
        normalized.insert("messages".to_string(), messages);
    }
    if let Some(Value::Object(options)) = object.get("options") {
        if let Some(value) = options.get("temperature") {
            normalized
                .entry("temperature")
                .or_insert_with(|| value.clone());
        }
        if let Some(value) = options.get("num_predict") {
            normalized
                .entry("max_tokens")
                .or_insert_with(|| value.clone());
        }
    }
    if !normalized.contains_key("max_tokens") && !normalized.contains_key("max_completion_tokens") {
        if let Some(value) = object.get("max_output_tokens") {
            normalized.insert("max_tokens".to_string(), value.clone());
        } else {
            normalized.insert(
                "max_tokens".to_string(),
                Value::from(DIRECT_OPENROUTER_DEFAULT_MAX_TOKENS),
            );
        }
    }
    normalized
        .entry("stream".to_string())
        .or_insert(Value::Bool(false));
    (CHAT_PATH.to_string(), Value::Object(normalized))
}

pub fn stream_requested(body: &Value) -> bool {
    body.get("stream").and_then(Value::as_bool) == Some(true)
}

/// Ollama streams by default unless the caller explicitly opts out.
pub fn ollama_stream_requested(body: &Value) -> bool {
    body.get("stream").and_then(Value::as_bool) != Some(false)
}

fn ensure_direct_completion_limit(object: &mut serde_json::Map<String, Value>) {
    if object.contains_key("max_tokens") || object.contains_key("max_completion_tokens") {
        return;
    }
    let limit = object
        .remove("max_output_tokens")
        .unwrap_or_else(|| Value::from(DIRECT_OPENROUTER_DEFAULT_MAX_TOKENS));
    object.insert("max_tokens".to_string(), limit);
}

pub fn openai_models(models: &[ModelDescriptor]) -> Value {
    Value::Object(serde_json::Map::from_iter([
        ("object".to_string(), Value::String("list".to_string())),
        (
            "data".to_string(),
            Value::Array(
                models
                    .iter()
                    .map(|model| {
                        json!({
                            "id": model.id,
                            "object": "model",
                            "created": 0,
                            "owned_by": model.owned_by,
                        })
                    })
                    .collect(),
            ),
        ),
    ]))
}

pub fn ollama_tags(models: &[ModelDescriptor]) -> Value {
    json!({
        "models": models
            .iter()
            .map(|model| {
                json!({
                    "name": model.id,
                    "model": model.id,
                    "modified_at": "1970-01-01T00:00:00Z",
                    "size": 0,
                    "digest": "zkapi",
                    "details": {
                        "format": "zkapi",
                        "family": "proxy",
                        "parameter_size": "n/a",
                        "quantization_level": "n/a",
                    },
                })
            })
            .collect::<Vec<_>>()
    })
}

pub fn chat_completion(model: &str, response: &CoreResponse) -> Value {
    if let Some(existing) = response
        .payload
        .as_ref()
        .filter(|value| value.get("choices").is_some())
    {
        return existing.clone();
    }

    let content = response_text(response);
    json!({
        "id": format!("chatcmpl-{}", response.client_request_id),
        "object": "chat.completion",
        "created": now_epoch_seconds(),
        "model": model,
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": content },
            "finish_reason": "stop",
        }],
        "usage": {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        },
        "zkapi": response_metadata(response),
    })
}

pub fn responses_api(model: &str, response: &CoreResponse) -> Value {
    if let Some(existing) = response
        .payload
        .as_ref()
        .filter(|value| value.get("output").is_some())
    {
        return existing.clone();
    }

    let content = response_text(response);
    json!({
        "id": format!("resp_{}", response.client_request_id),
        "object": "response",
        "created_at": now_epoch_seconds(),
        "status": "completed",
        "model": model,
        "output": [{
            "type": "message",
            "role": "assistant",
            "content": [{
                "type": "output_text",
                "text": content,
            }],
        }],
        "zkapi": response_metadata(response),
    })
}

pub fn ollama_chat(model: &str, response: &CoreResponse) -> Value {
    if let Some(existing) = response
        .payload
        .as_ref()
        .filter(|value| value.get("message").is_some())
    {
        return existing.clone();
    }

    let content = response_text(response);
    let (prompt_tokens, completion_tokens) = response_usage(response);
    json!({
        "model": model,
        "created_at": "1970-01-01T00:00:00Z",
        "message": {
            "role": "assistant",
            "content": content,
        },
        "done": true,
        "done_reason": "stop",
        "total_duration": 0,
        "load_duration": 0,
        "prompt_eval_count": prompt_tokens,
        "eval_count": completion_tokens,
        "zkapi": response_metadata(response),
    })
}

fn response_text(response: &CoreResponse) -> String {
    match response.payload.as_ref() {
        Some(Value::String(text)) => text.clone(),
        Some(value) => {
            // Prefer the assistant text from an OpenAI chat-completion
            // (`choices[0].message.content`) or an OpenAI Responses
            // (`output[0].content[0].text`) payload, so the Ollama/Responses
            // shims surface real content from an OpenAI-format upstream rather
            // than the whole JSON blob.
            if let Some(text) = value
                .get("choices")
                .and_then(|c| c.get(0))
                .and_then(|c| c.get("message"))
                .and_then(|m| m.get("content"))
                .and_then(Value::as_str)
            {
                return text.to_string();
            }
            if let Some(text) = value
                .get("output")
                .and_then(|o| o.get(0))
                .and_then(|o| o.get("content"))
                .and_then(|c| c.get(0))
                .and_then(|c| c.get("text"))
                .and_then(Value::as_str)
            {
                return text.to_string();
            }
            value.to_string()
        }
        None => response.raw_payload.clone(),
    }
}

/// Pull (prompt_tokens, completion_tokens) from an OpenAI-format `usage` block.
fn response_usage(response: &CoreResponse) -> (u64, u64) {
    let usage = response.payload.as_ref().and_then(|v| v.get("usage"));
    let prompt = usage
        .and_then(|u| u.get("prompt_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let completion = usage
        .and_then(|u| u.get("completion_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    (prompt, completion)
}

fn response_metadata(response: &CoreResponse) -> Value {
    json!({
        "response_code": response.response_code,
        "charge_applied": response.charge_applied,
        "remaining_balance": response.remaining_balance,
        "next_anchor": response.next_anchor,
    })
}

fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use zkapi_types::Felt252;

    use super::*;

    fn response(payload: Option<Value>) -> CoreResponse {
        CoreResponse {
            client_request_id: "req-1".to_string(),
            response_code: 200,
            raw_payload: payload.clone().unwrap_or_else(|| json!("hi")).to_string(),
            payload,
            charge_applied: 7,
            next_anchor: Felt252::from_u64(9),
            remaining_balance: Some(42),
        }
    }

    #[test]
    fn chat_completion_passthroughs_existing_shape() {
        let payload = json!({
            "choices": [{ "message": { "role": "assistant", "content": "ok" } }]
        });
        let result = chat_completion("demo", &response(Some(payload.clone())));
        assert_eq!(result, payload);
    }

    #[test]
    fn chat_completion_synthesizes_shape() {
        let result = chat_completion("demo", &response(Some(json!({"foo": "bar"}))));
        assert_eq!(result["object"], "chat.completion");
        assert_eq!(result["model"], "demo");
        assert_eq!(
            result["choices"][0]["message"]["content"],
            "{\"foo\":\"bar\"}"
        );
    }

    #[test]
    fn ollama_chat_extracts_openai_content_and_usage() {
        // A real OpenAI-format upstream response (what the metered provider
        // returns) must surface as proper Ollama content + token counts.
        let payload = json!({
            "choices": [{ "message": { "role": "assistant", "content": "ollama shim works" } }],
            "usage": { "prompt_tokens": 12, "completion_tokens": 4, "total_tokens": 16 }
        });
        let result = ollama_chat("gpt-4o-mini", &response(Some(payload)));
        assert_eq!(result["message"]["content"], "ollama shim works");
        assert_eq!(result["prompt_eval_count"], 12);
        assert_eq!(result["eval_count"], 4);
        assert_eq!(result["done"], true);
    }

    #[test]
    fn responses_api_extracts_openai_chat_content() {
        let payload = json!({
            "choices": [{ "message": { "role": "assistant", "content": "hello there" } }]
        });
        let result = responses_api("gpt-4o-mini", &response(Some(payload)));
        assert_eq!(result["output"][0]["content"][0]["text"], "hello there");
    }

    #[test]
    fn ollama_tags_render_models() {
        let tags = ollama_tags(&[ModelDescriptor::new("demo")]);
        assert_eq!(tags["models"][0]["name"], "demo");
    }

    #[test]
    fn direct_openrouter_normalization_stays_local_and_non_streaming() {
        let (path, body) = openrouter_request(
            "/v1/responses",
            json!({"model": "openai/gpt-4o-mini", "input": "secret prompt"}),
        );
        assert_eq!(path, "/chat/completions");
        assert_eq!(body["messages"][0]["content"], "secret prompt");
        assert_eq!(body["max_tokens"], DIRECT_OPENROUTER_DEFAULT_MAX_TOKENS);
        assert_eq!(body["stream"], false);

        let (_, chat) = openrouter_request(
            "/v1/chat/completions",
            json!({
                "model": "openai/gpt-4o-mini",
                "messages": [{"role": "user", "content": "secret prompt"}]
            }),
        );
        assert_eq!(chat["max_tokens"], DIRECT_OPENROUTER_DEFAULT_MAX_TOKENS);

        let (_, ollama) = openrouter_request(
            "/api/chat",
            json!({
                "model": "openai/gpt-4o-mini",
                "messages": [{"role": "user", "content": "secret prompt"}],
                "stream": false
            }),
        );
        assert_eq!(ollama["max_tokens"], DIRECT_OPENROUTER_DEFAULT_MAX_TOKENS);
    }

    #[test]
    fn direct_openrouter_preserves_explicit_completion_limits() {
        let (_, chat) = openrouter_request(
            "/v1/chat/completions",
            json!({
                "model": "openai/gpt-4o-mini",
                "messages": [{"role": "user", "content": "hello"}],
                "max_completion_tokens": 77
            }),
        );
        assert_eq!(chat["max_completion_tokens"], 77);
        assert!(chat.get("max_tokens").is_none());

        let (_, responses) = openrouter_request(
            "/v1/responses",
            json!({
                "model": "openai/gpt-4o-mini",
                "input": "hello",
                "max_output_tokens": 88
            }),
        );
        assert_eq!(responses["max_tokens"], 88);
    }

    #[test]
    fn direct_openrouter_preserves_streaming_requests() {
        let (_, chat) = openrouter_request(
            "/v1/chat/completions",
            json!({
                "model": "openai/gpt-5.6-sol",
                "stream": true,
                "messages": [{"role": "user", "content": "hello"}]
            }),
        );
        assert_eq!(chat["stream"], true);
        assert!(stream_requested(&chat));
    }

    #[test]
    fn ollama_streaming_defaults_on_and_can_be_disabled() {
        assert!(ollama_stream_requested(&json!({})));
        assert!(ollama_stream_requested(&json!({ "stream": true })));
        assert!(!ollama_stream_requested(&json!({ "stream": false })));
    }
}
