//! `lsend send` subcommand
//!
//! Transmits files to a LocalSend peer, supporting target resolution, pinned TLS verification,
//! and progress visualization.

#[cfg(unix)]
use crate::ipc_client::IpcClient;
use crate::tls_client::{create_pinned_client, create_probe_client};
use console::style;
use futures_util::StreamExt;
use localsend_protocol::{
    DeviceType, FileMetadata, InfoResponseDto, PrepareUploadRequest, PrepareUploadResponse,
    ProtocolType, RegisterDto,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

/// Result summary serialized when `--json` flag is provided.
#[derive(serde::Serialize)]
pub struct SendResultOutput {
    pub success: bool,
    pub session_id: String,
    pub target_ip: String,
    pub target_port: u16,
    pub target_alias: String,
    pub files: Vec<SentFileInfo>,
}

#[derive(serde::Serialize)]
pub struct SentFileInfo {
    pub file_name: String,
    pub size: u64,
    pub sha256: String,
}

/// Execute the `lsend send` command.
pub async fn run(
    target: &str,
    file_paths: &[PathBuf],
    pin: Option<String>,
    fingerprint: Option<String>,
    standalone: bool,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if file_paths.is_empty() {
        return Err("No files specified for transfer".into());
    }

    // 1. Verify that all target files exist
    for path in file_paths {
        if !path.is_file() {
            return Err(format!("File not found or not a regular file: {}", path.display()).into());
        }
    }

    // Attempt to verify running daemon if not standalone
    if !standalone {
        #[cfg(unix)]
        if let Ok(mut ipc) = IpcClient::connect(Path::new(IpcClient::DEFAULT_PATH)).await {
            if let Ok(status) = ipc.get_status().await {
                if !json_output {
                    eprintln!(
                        "{}",
                        style(format!(
                            "Verified connection to local daemon (uptime {}s)",
                            status.uptime_secs
                        ))
                        .dim()
                    );
                }
            }
        }
    }

    // 2. Target Resolution (IP or Alias)
    let (target_ip, target_port, known_alias, known_fp) = resolve_target(target).await?;

    let effective_fingerprint = match fingerprint {
        Some(fp) => fp,
        None => match known_fp {
            Some(fp) => fp,
            None => {
                // Probe peer via HTTP info route to discover certificate fingerprint
                probe_peer_fingerprint(target_ip, target_port).await?
            }
        },
    };

    if !json_output {
        let peer_desc = known_alias.as_deref().unwrap_or(target);
        eprintln!(
            "{}",
            style(format!(
                "Initiating transfer to '{}' ({}:{}) [FP: {}]",
                peer_desc,
                target_ip,
                target_port,
                if effective_fingerprint.len() > 16 {
                    format!("{}...", &effective_fingerprint[..16])
                } else {
                    effective_fingerprint.clone()
                }
            ))
            .cyan()
            .bold()
        );
    }

    // 3. Compute file metadata & SHA-256 hashes
    let mut files_map = HashMap::new();
    let mut files_summary = Vec::new();

    for path in file_paths {
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();

        let metadata = tokio::fs::metadata(path).await?;
        let size = metadata.len();

        let content = tokio::fs::read(path).await?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let sha256_hex = hex::encode_upper(hasher.finalize());

        let file_id = uuid::Uuid::new_v4().to_string();
        files_map.insert(
            file_id.clone(),
            FileMetadata {
                id: file_id,
                file_name: file_name.clone(),
                size,
                file_type: "application/octet-stream".to_string(),
                sha256: Some(sha256_hex.clone()),
                preview: None,
                metadata: None,
            },
        );

        files_summary.push(SentFileInfo {
            file_name,
            size,
            sha256: sha256_hex,
        });
    }

    // 4. Construct pinned TLS client
    let client = create_pinned_client(&effective_fingerprint)?;

    // 5. Send POST /api/localsend/v2/prepare-upload
    let mut prepare_url =
        format!("https://{target_ip}:{target_port}/api/localsend/v2/prepare-upload");
    if let Some(ref p) = pin {
        prepare_url.push_str(&format!("?pin={p}"));
    }

    let our_info = RegisterDto {
        alias: "lsend-cli".to_string(),
        version: "2.0".to_string(),
        device_model: Some("CLI Utility".to_string()),
        device_type: Some(DeviceType::Headless),
        fingerprint: "LSEND_CLI_CLIENT_FP".to_string(),
        port: 0,
        protocol: ProtocolType::Https,
        download: false,
    };

    let prepare_req = PrepareUploadRequest {
        info: our_info,
        files: files_map.clone(),
    };

    if !json_output {
        eprintln!("{}", style("Requesting transfer session approval...").dim());
    }

    let prep_resp = client.post(&prepare_url).json(&prepare_req).send().await?;

    let prep_status = prep_resp.status();
    if prep_status == reqwest::StatusCode::UNAUTHORIZED {
        return Err("Authorization failed: incorrect or missing PIN code.".into());
    } else if prep_status == reqwest::StatusCode::FORBIDDEN {
        return Err("Transfer rejected by remote peer or approval timed out.".into());
    } else if prep_status == reqwest::StatusCode::CONFLICT {
        return Err("Remote peer is currently in another transfer session.".into());
    } else if !prep_status.is_success() {
        let err_body = prep_resp.text().await.unwrap_or_default();
        return Err(format!("Prepare-upload failed ({prep_status}): {err_body}").into());
    }

    let prep_data: PrepareUploadResponse = prep_resp.json().await?;
    let session_id = prep_data.session_id;

    if !json_output {
        eprintln!(
            "{}",
            style(format!(
                "Session accepted: {session_id}. Streaming files..."
            ))
            .green()
        );
    }

    // 6. Stream each file to POST /api/localsend/v2/upload
    for (idx, path) in file_paths.iter().enumerate() {
        let (file_id, file_meta) = files_map
            .iter()
            .find(|(_, meta)| {
                meta.file_name
                    == path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or_default()
            })
            .ok_or("Internal mapping error")?;

        let token = prep_data
            .files
            .get(file_id)
            .ok_or_else(|| format!("No upload token granted for file {}", file_meta.file_name))?;

        let upload_url = format!(
            "https://{target_ip}:{target_port}/api/localsend/v2/upload?sessionId={session_id}&fileId={file_id}&token={token}"
        );

        let pb = if !json_output && console::user_attended() {
            let p = indicatif::ProgressBar::new(file_meta.size);
            p.set_style(
                indicatif::ProgressStyle::default_bar()
                    .template(
                        "[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}",
                    )
                    .unwrap()
                    .progress_chars("#>-"),
            );
            p.set_message(format!(
                "[{}/{}] {}",
                idx + 1,
                file_paths.len(),
                file_meta.file_name
            ));
            Some(p)
        } else {
            None
        };

        let file = tokio::fs::File::open(path).await?;
        let reader_stream = tokio_util::io::ReaderStream::new(file);
        let pb_clone = pb.clone();

        let stream = reader_stream.map(move |chunk| {
            if let Ok(ref bytes) = chunk
                && let Some(ref p) = pb_clone
            {
                p.inc(bytes.len() as u64);
            }
            chunk
        });

        let body = reqwest::Body::wrap_stream(stream);
        let upload_resp = client.post(&upload_url).body(body).send().await?;

        if !upload_resp.status().is_success() {
            let err_body = upload_resp.text().await.unwrap_or_default();
            if let Some(p) = pb {
                p.abandon();
            }
            return Err(format!("Upload failed for {}: {err_body}", file_meta.file_name).into());
        }

        if let Some(p) = pb {
            p.finish_with_message(format!("{}: Complete", file_meta.file_name));
        } else if !json_output {
            eprintln!(
                "[{}/{}] Transferred {}",
                idx + 1,
                file_paths.len(),
                file_meta.file_name
            );
        }
    }

    if json_output {
        let output = SendResultOutput {
            success: true,
            session_id,
            target_ip: target_ip.to_string(),
            target_port,
            target_alias: known_alias.unwrap_or_else(|| target.to_string()),
            files: files_summary,
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!(
            "\n{}",
            style(format!(
                "Successfully transferred {} file(s) to {}",
                file_paths.len(),
                target
            ))
            .green()
            .bold()
        );
    }

    Ok(())
}

/// Resolve target argument to IP, port, alias, and optional known fingerprint.
async fn resolve_target(
    target: &str,
) -> Result<(IpAddr, u16, Option<String>, Option<String>), Box<dyn std::error::Error>> {
    // 1. Try parsing directly as SocketAddr
    if let Ok(addr) = SocketAddr::from_str(target) {
        return Ok((addr.ip(), addr.port(), None, None));
    }

    // 2. Try parsing directly as IpAddr
    if let Ok(ip) = IpAddr::from_str(target) {
        return Ok((ip, 53317, None, None));
    }

    // 3. Try checking local daemon IPC peer cache
    #[cfg(unix)]
    {
        if let Ok(mut client) = IpcClient::connect(Path::new(IpcClient::DEFAULT_PATH)).await {
            if let Ok(peers) = client.get_peers().await {
                for p in peers {
                    if p.alias.eq_ignore_ascii_case(target) {
                        return Ok((p.ip, p.port, Some(p.alias), Some(p.fingerprint)));
                    }
                }
            }
        }
    }

    // 4. Fallback: query multicast discovery briefly (1 second) to find matching alias
    let registry = localsend_discovery::PeerRegistry::new();
    let config = localsend_discovery::MulticastConfig {
        port: 53317,
        local_fingerprint: "RESOLVER_FP".to_string(),
        heartbeat_interval: std::time::Duration::from_millis(500),
    };

    if let Ok(engine) = localsend_discovery::DiscoveryEngine::new(config, registry.clone()) {
        let announcement = localsend_protocol::MulticastAnnouncement::new(
            "lsend-resolver",
            "RESOLVER_FP",
            53317,
            ProtocolType::Https,
        );
        let (rx, hb) = engine.start(announcement);
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        engine.stop();
        rx.abort();
        hb.abort();
    }

    for p in registry.list().await {
        if p.alias.eq_ignore_ascii_case(target) {
            return Ok((p.ip, p.port, Some(p.alias), Some(p.fingerprint)));
        }
    }

    Err(format!(
        "Target '{}' could not be resolved to an IP address or discovered peer alias.",
        target
    )
    .into())
}

/// Probes target node via unpinned HTTP probe to discover certificate fingerprint.
async fn probe_peer_fingerprint(
    target_ip: IpAddr,
    port: u16,
) -> Result<String, Box<dyn std::error::Error>> {
    let probe_client = create_probe_client();
    let info_url = format!("https://{target_ip}:{port}/api/localsend/v2/info");

    let res = probe_client.get(&info_url).send().await?;
    if res.status().is_success() {
        let dto: InfoResponseDto = res.json().await?;
        return Ok(dto.fingerprint);
    }

    Err(format!(
        "Failed to probe target peer info at {info_url} (HTTP {})",
        res.status()
    )
    .into())
}
