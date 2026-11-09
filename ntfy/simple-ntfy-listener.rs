#!/usr/bin/env rust-script
//! ```cargo
//! [package]
//! name = "simple-ntfy-listener"
//! [profile.release]
//! strip = true
//! codegen-units = 1
//! panic = "abort"
//! [build]
//! [dependencies]
//! ureq = { version = "3", default-features = false, features = ["platform-verifier", "rustls"] }
//! tinyjson = "2"
//! notify-rust = { version = "4", default-features = false, features = ["dbus"] }
//! env_logger = "0.11"
//! log = "*"
//! anyhow = "1"
//! ```

use anyhow::{anyhow, bail, Context, Result};
use log::{debug, error, info, warn};
use notify_rust::Notification;
use std::{
    cmp::min,
    collections::HashMap,
    io::{BufRead, BufReader, Read},
    process::exit,
    time::Duration,
};
use tinyjson::JsonValue;
use ureq::{tls, Agent};

// ntfy sends keepalive every 60 seconds; includes 15 seconds grace period
const PER_READ_TIMEOUT: u64 = 75;

// Relative to config dir (XDG_CONFIG_HOME, then $HOME/.config)
const CONFIG_LOCATION: &str = "/ntfy/credentials";

const HELP_TEXT: &str = "
Usage: ./simple-ntfy-listener.rs [ntfy-instance-root] [topic 1] [topic 2] [...]

Example: ./simple-ntfy-listener.rs https://ntfy.sh topic1 topic2


To use authentication, include the contentents of the desired Authorization header at $XDG_CONFIG_HOME/ntfy/credentials or $HOME/.config/ntfy/credentials.

Example: Bearer xxxxxxxxxxxx
";

fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let mut args: std::env::Args = std::env::args();

    let base_url = args.nth(1);
    if base_url.is_none() {
        println!("{HELP_TEXT}");
        exit(1);
    };
    let base_url = base_url.unwrap();
    if !base_url.starts_with("https://") && !base_url.starts_with("http://") {
        bail!(format!("First argument must be a valid URL!\n{HELP_TEXT}"))
    };

    let mut topics = args
        .next()
        .context(anyhow!(format!("No topics provided!\n{HELP_TEXT}")))?;
    args.for_each(|topic| {
        topics.push(',');
        topics.push_str(topic.as_str());
    });

    let url = format!("{base_url}/{topics}/sse");

    let config_root;
    if let Some(resolved_config_root) = option_env!("XDG_CONFIG_HOME") {
        config_root = resolved_config_root.to_owned();
    } else {
        config_root = format!(
            "{}/.config",
            option_env!("HOME")
                .ok_or(anyhow!("Either $XDG_CONFIG_HOME or $HOME has to be set!"))?
        );
    };
    let mut state = State {
        credentials: std::fs::read_to_string(format!("{config_root}/{CONFIG_LOCATION}"))
            .ok()
            .map(|creds| creds.trim().to_owned())
            .or_else(|| {
                warn!("No credentials found or not readable");
                None
            }),

        url,
        last_msg_id: [0; 12], // One message id has 12 UTF-8 chars
        backoff: Duration::from_secs(1),
    };

    let config = ureq::Agent::config_builder()
        // We really want to use PlatformVerifier certs here as CA certificates are built into the
        // binary with the default rustls provider. That would result in locally installed
        // self-signed certificates not working.
        .tls_config(
            tls::TlsConfig::builder()
                .root_certs(tls::RootCerts::PlatformVerifier)
                .build(),
        )
        .timeout_per_read(Some(Duration::from_secs(PER_READ_TIMEOUT)))
        .build();

    loop {
        let Ok(res) = create_new_request(&state, config.new_agent()) else {
            error!(
                "Unable to connect.\nWaiting {} seconds..",
                state.backoff.as_secs()
            );
            std::thread::sleep(state.backoff);
            continue;
        };
        state.backoff = std::time::Duration::from_secs(1);
        let result = consume_reader(res, &mut state.last_msg_id);

        if let Err(err) = result {
            error!(
                "Error occurred ({err}), retrying in {} seconds...",
                state.backoff.as_secs_f32()
            );
            std::thread::sleep(state.backoff);
        }
        state.backoff = min(state.backoff * 2, Duration::from_secs(30));
    }
}

fn create_new_request(state: &State, agent: Agent) -> Result<BufReader<impl Read>, anyhow::Error> {
    // There's no UTF-8 char that is a nullbyte.
    // So if the last message ID is empty, we create an url without the `since=` postfix
    //
    // Using &String here as a stringslice would require an additional allocation in the else
    // block
    let url: &String = if state.last_msg_id[0] != 0 {
        &format!(
            "{}?since={}",
            state.url,
            str::from_utf8(&state.last_msg_id)?
        )
    } else {
        &state.url
    };
    debug!("url={}", url);

    let agent = agent.get(url);

    let agent = if let Some(creds) = &state.credentials {
        agent.header("Authorization", creds)
    } else {
        agent
    };

    let res = agent.call()?;

    let (_, body) = res.into_parts();
    println!("Connection to {} established!", state.url);
    info!("Last message id: {}", str::from_utf8(&state.last_msg_id)?);
    Ok(BufReader::new(body.into_reader()))
}

fn consume_reader(
    reader: BufReader<impl Read>,
    last_msg_id: &mut [u8; 12],
) -> Result<(), anyhow::Error> {
    for line in reader.lines() {
        let line = line?;
        let response = Response::parse(&line);
        match response {
            Response::Empty => {}
            Response::Keepalive { id } => {
                *last_msg_id = id;
            }
            Response::Open { id } => {
                *last_msg_id = id;
            }
            Response::Message { id, content } => {
                Notification::new().summary("ntfy").body(&content).show()?;
                info!("Received notification: {}", content);
                *last_msg_id = id;
            }
            Response::Unknown { id, event_name } => {
                // Keeping this silent for now as *hypothetically* an update *could* introduce a new
                // event type in which case we don't want to spam the user..
                warn!("Received unknown Event of type {}", event_name);
                *last_msg_id = id;
            }
            Response::Malformed { content, error } => {
                let msg = format!(
                    "Received malformed response: {}\n\
                    Is there an ntfy topic over SSE at the used URL?\n\
                    Content: {}",
                    error, content
                );
                msg.lines().for_each(|e| error!("{}", e));
                Notification::new()
                    .summary("ntfy error")
                    .body(&msg)
                    .show()?;
            }
        };
    }
    Ok(())
}

struct State {
    credentials: Option<String>,
    // IDs are 12-char UTF-8 Strings
    last_msg_id: [u8; 12],
    url: String,
    backoff: Duration,
}

impl Response {
    fn parse(data: &str) -> Self {
        let res: Result<Response, anyhow::Error> = (|| {
            debug!("line={}", data);
            if data.is_empty() || data.starts_with("event: ") {
                return Ok(Response::Empty);
            };
            let data = data
                .strip_prefix("data: ")
                .ok_or(anyhow!("Response doesn't start with 'data: '"))?;
            if data.is_empty() {
                return Ok(Response::Empty);
            };

            let data_parsed = data.parse::<JsonValue>()?;

            let map = data_parsed
                .get::<HashMap<String, JsonValue>>()
                .ok_or(anyhow!("Response doesn't contain an object"))?;

            let event = map
                .get("event")
                .ok_or(anyhow!("No field named event in Response object"))?
                .get::<String>()
                .ok_or(anyhow!("Field event in response isn't a String"))?
                .trim();

            debug!(
                "id_bytes={:?}",
                map.get("id")
                    .ok_or(anyhow!("No field named id in Response object"))?
                    .get::<String>()
                    .ok_or(anyhow!("Field id in response isn't a String"))?
                    .trim()
                    .as_bytes()
            );

            let id: [u8; 12] = map
                .get("id")
                .ok_or(anyhow!("No field named id in Response object"))?
                .get::<String>()
                .ok_or(anyhow!("Field id in response isn't a String"))?
                .trim()
                .as_bytes()
                .try_into()
                .context("Response ID wasn't in expected format")?;

            debug!("id={}", str::from_utf8(&id)?);
            debug!("event={}", event);

            match event.trim() {
                "message" => {
                    let msg: &String = map
                        .get("message")
                        .ok_or(anyhow!("Message content missing".to_owned()))?
                        .get()
                        .unwrap();
                    Ok(Response::Message {
                        id,
                        content: msg.clone(),
                    })
                }
                "keepalive" => Ok(Response::Keepalive { id }),
                "open" => Ok(Response::Open { id }),
                e => Ok(Response::Unknown {
                    id,
                    event_name: e.to_owned(),
                }),
            }
        })();

        match res {
            Ok(o) => o,
            Err(e) => Response::Malformed {
                content: data.to_owned(),
                error: e.to_string(),
            },
        }
    }
}

enum Response {
    Empty,
    Keepalive { id: [u8; 12] },
    Open { id: [u8; 12] },
    Message { id: [u8; 12], content: String },
    Unknown { id: [u8; 12], event_name: String },
    Malformed { content: String, error: String },
}
