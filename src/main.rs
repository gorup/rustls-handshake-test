use std::net::*;
use rustls::*;
use std::io::BufReader;
use webpki::DNSNameRef;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use env_logger::Builder;
use log::LevelFilter;

#[macro_use]
extern crate log;

static ADDR: &str = "127.0.0.1:51301";

fn main() {
    Builder::new().filter_level(LevelFilter::Trace).init();
    println!("Hello, world!");

    let server_runner_handle = thread::spawn(move || {
        server_runner();
    });

    info!("Sleep to make sure server is ready");
    thread::sleep(Duration::from_secs(3));

    let client_runner_handle = thread::spawn(move || {
        client_runner();
    });

    server_runner_handle.join().unwrap();
    client_runner_handle.join().unwrap();
}

fn server_runner() {
    info!("SERVER spinning up listener");
    let listener = TcpListener::bind(ADDR).unwrap();
    info!("SERVER done spinning up listener, now waiting on accept..");
    let (mut stream, _) = listener.accept().unwrap();
    info!("SERVER stream accepted! Will set up session and complete io");
    let mut session = server_session();

    let mut i = 0;
    loop {
        let (num_read, num_write) = session.complete_io(&mut stream).unwrap();
        info!("SERVER i={} num_read={} num_wrote={} is_handshaking={} wants_read={} wants_write={}",
            i,
            num_read,
            num_write,
            session.is_handshaking(),
            session.wants_read(),
            session.wants_write(),
        );
        if !session.is_handshaking() {
            error!("SERVER Session has completed handshake! 📣 📣");
        }
        i += 1;
    }
}

fn client_runner() {
    info!("CLIENT Connecting tcp stream");
    let mut stream = TcpStream::connect(ADDR).unwrap();
    info!("CLIENT Done connecting TCP, now setting up session and will complete io");
    let mut session = client_session();

    let mut i = 0;
    loop {
        let (num_read, num_write) = session.complete_io(&mut stream).unwrap();
        info!("CLIENT i={} num_read={} num_wrote={} is_handshaking={} wants_read={} wants_write={}",
            i,
            num_read,
            num_write,
            session.is_handshaking(),
            session.wants_read(),
            session.wants_write(),
        );
        if !session.is_handshaking() {
            error!("CLIENT Session has completed handshake! 📣 📣");
        }
        i += 1;
        thread::sleep(Duration::from_secs(5));
    }
}

pub fn server_session() -> ServerSession {
    let mut root_cert_store = RootCertStore::empty();
    root_cert_store
        .add_pem_file(&mut to_bufreader(ROTATE_SERVER_CA_PEM))
        .unwrap();

    //let server_cert_verifier = AllowAnyAuthenticatedClient::new(root_cert_store);
    let server_cert_verifier = NoClientAuth::new();
    let mut config = ServerConfig::new(server_cert_verifier);
    config
        .set_single_cert(
            certificate_chain(ROTATE_SERVER_PEM),
            key_der(ROTATE_SERVER_KEY),
        )
        .unwrap();

    ServerSession::new(&Arc::new(config))
}

pub fn client_session() -> ClientSession {
    let mut config = ClientConfig::new();
    config
        .root_store
        .add_pem_file(&mut to_bufreader(ROTATE_SERVER_CA_PEM))
        .unwrap();
    //config.set_single_client_cert(certificate_chain(ROTATE_SERVER_PEM), key_der(ROTATE_SERVER_KEY));

    ClientSession::new(
        &Arc::new(config),
        DNSNameRef::try_from_ascii_str(GOOD_SNI).unwrap(),
    )
}

fn certificate_chain(cert_str: &str) -> Vec<Certificate> {
    rustls::internal::pemfile::certs(&mut to_bufreader(cert_str)).unwrap()
}

fn key_der(key_str: &str) -> PrivateKey {
    let mut reader = to_bufreader(key_str);
    if let Ok(mut keys) = rustls::internal::pemfile::rsa_private_keys(&mut reader) {
        assert_eq!(1, keys.len());
        return keys.pop().unwrap();
    }

    let mut keys = rustls::internal::pemfile::rsa_private_keys(&mut reader)
        .expect("file contains invalid rsa private key");

    assert_eq!(1, keys.len());
    keys.pop().unwrap()
}

fn to_bufreader(strizle: &str) -> BufReader<&[u8]> {
    BufReader::new(strizle.as_bytes())
}

static ROTATE_SERVER_CA_PEM: &'static str = "-----BEGIN CERTIFICATE-----
MIIDyjCCArKgAwIBAgIJAPPg47SGcnF0MA0GCSqGSIb3DQEBCwUAMHoxCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJXQTEQMA4GA1UEBwwHU2VhdHRsZTEQMA4GA1UECgwH
RWJiZmxvdzEbMBkGA1UEAwwSVGVzdCBDQSBmb3IgUm90YXRlMR0wGwYJKoZIhvcN
AQkBFg5yeWFuQGdvcnVwLmNvbTAeFw0xOTAxMzAyMzU3MjJaFw0zMzA4MDQyMzU3
MjJaMHoxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJXQTEQMA4GA1UEBwwHU2VhdHRs
ZTEQMA4GA1UECgwHRWJiZmxvdzEbMBkGA1UEAwwSVGVzdCBDQSBmb3IgUm90YXRl
MR0wGwYJKoZIhvcNAQkBFg5yeWFuQGdvcnVwLmNvbTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAK1ryhEw77i2gNFeKfJosucYOnK/r28RqDiZH/3viBMu
BXUQNzIhxX/3D1ARfBbjtUS4hYILImy5ffRbnF2jfkkBvgvpKbsbwW0ypIUMqB7O
ajkDvipUTZJm6ZPgHcYJmJu+l0OK8viZFfxUIzy5Qo7NAjs1XH4hy/m/j+/AXjhH
c6KnojcZzzAfvEhVMw9pjkxDixKEvGL/6UHFpwcOHdPqzPwxBkk4c1BForNtJaSD
13GXltVGfRFyuNu/AzLIgVN0151UzEVXpCIcwtJjO1bpbNMYUyCdTKXlM5Z9OeO7
dgMaDKHhvwsZUx5W2QaQNvzcqNAHGYi8uUJjD8v84usCAwEAAaNTMFEwHQYDVR0O
BBYEFCvjQUVxN7c8QNugm2JEJk0fis7iMB8GA1UdIwQYMBaAFCvjQUVxN7c8QNug
m2JEJk0fis7iMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAIhy
waZehAxC2K2a6QS9rvdD38GyUYaVTO9ZvakZBtk/AfNuRGffMybLV28BH9OhvXal
qQpiZUxhTHddGNDnvDel+Oz0saCB9fw+KYJQFDesMiH6FkC9NGPUdWKX/uHYEWLc
4BEl4Hf8/pO4Dq36ig0F+1dJnVmcaQfs6gy1mC2BNWyCf/aHCZ+RI+hw4+o5wwQ7
9RLOeJWe2AE8AgKt1FxsYGTYcQnX8QS3dMAHmYa0xO4m6dHlPtPaiVCOmNs9ql61
BnFo+GuHI+dXmuyRKbuvxHBp+P6Tfhc73COp0+xKCIM59FPpv0Sn4MPgF9mqVUGU
hiFQDxck7yF8ylELbts=
-----END CERTIFICATE-----
";

static ROTATE_SERVER_PEM: &'static str = "-----BEGIN CERTIFICATE-----
MIIEBzCCAu+gAwIBAgIJALv/t3svGx2JMA0GCSqGSIb3DQEBCwUAMHoxCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJXQTEQMA4GA1UEBwwHU2VhdHRsZTEQMA4GA1UECgwH
RWJiZmxvdzEbMBkGA1UEAwwSVGVzdCBDQSBmb3IgUm90YXRlMR0wGwYJKoZIhvcN
AQkBFg5yeWFuQGdvcnVwLmNvbTAeFw0xOTAyMTAwMTM4NDZaFw0yNDAyMDkwMTM4
NDZaMIGKMQswCQYDVQQGEwJVUzELMAkGA1UECAwCV0ExEDAOBgNVBAcMB1NlYXR0
bGUxEDAOBgNVBAoMB0ViYmZsb3cxDzANBgNVBAsMBlNvY2tldDEaMBgGA1UEAwwR
c29ja2V0LmViYmZsb3cuaW8xHTAbBgkqhkiG9w0BCQEWDnJ5YW5AZ29ydXAuY29t
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtg/A6xh6TIqweW5D4fMG
zq8IPuJ3R8593E7N8BbSlehCex6QH+dKkHFo+Lu5+igDOPBH9jpOiP5usvlInSaG
Bkv5HqdbIDxnsA0KJBks/5tQEH1Ru1Y+NcRZW8HN7Y6BeHkpLeaYgFpSWQHbapFM
yynRdO1wAH8PqtsGM90/GAkwAjxB97cODskl4vGVENGVCqshY5IsWFBEN8DN+1Sq
LKMX7G6FoNOJV8K3sHDKHd4TJfPxFqdHUpUak4AQv9fhud8NtPpbdGs8CT9QFU57
OOBx7SFpvBs7Nplz/DP2lftGJpytt8Z8AAIsl2ss1ouPnRxVUaFGKWPf2FzxwjhZ
1wIDAQABo38wfTAfBgNVHSMEGDAWgBQr40FFcTe3PEDboJtiRCZNH4rO4jAJBgNV
HRMEAjAAMAsGA1UdDwQEAwIE8DBCBgNVHREEOzA5ghhzZXJ2ZXIuc29ja2V0LmVi
YmZsb3cuaW+CHSouY3VzdG9tZXIxLnNvY2tldC5lYmJmbG93LmlvMA0GCSqGSIb3
DQEBCwUAA4IBAQAMQBQQIL8JXk9oHnkHWZGV1rgKGibwlq+JSsGK8kJcuZJKR8yM
m5yebaGcwJf6x6JgUjXOxfnE/0Z0Wqp2FsxpwSvOjSuMtXF8eMd0SYsPz7IIx2XB
Uf5s93Np7lSMYW9JsVsmJoThpZTHeEcfZXfsZaw4ax127ZXqV8wGORNFlMPhNHom
Uojs1dKQOx5j3HezXxDlJdP9MT/IIcgZuVr9Gc7qzcE2D3xXDIBv21m9zO28BH0x
3HOkVNiv/euwBDyiltg93ZfkPqq+P2a9PWg2Nll/js05pn1sLtU120+Pk+8+NQ9t
pTUWAvX5OMIgScLPPqJ/M8Umdd+WS72XyNgv
-----END CERTIFICATE-----
";

static ROTATE_SERVER_KEY: &'static str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtg/A6xh6TIqweW5D4fMGzq8IPuJ3R8593E7N8BbSlehCex6Q
H+dKkHFo+Lu5+igDOPBH9jpOiP5usvlInSaGBkv5HqdbIDxnsA0KJBks/5tQEH1R
u1Y+NcRZW8HN7Y6BeHkpLeaYgFpSWQHbapFMyynRdO1wAH8PqtsGM90/GAkwAjxB
97cODskl4vGVENGVCqshY5IsWFBEN8DN+1SqLKMX7G6FoNOJV8K3sHDKHd4TJfPx
FqdHUpUak4AQv9fhud8NtPpbdGs8CT9QFU57OOBx7SFpvBs7Nplz/DP2lftGJpyt
t8Z8AAIsl2ss1ouPnRxVUaFGKWPf2FzxwjhZ1wIDAQABAoIBAQCmYe1HrP4Pt2uh
/fBRrR0ahAGAHs0ttXt2fBpegS0AzNr806iZT3HoYYyyTDWhdTHEtmq9jvm43vVh
4MnIvK0dUg8gQYfZBPspfDE5XjyueE0KVMz97Mo7ru6PGaXNpT+TTv8gMK5MFr9N
EpJoaNOKk/QU7O0/tt8loLahbV+84RRrF1muEsgz6QBfzdDrUzTKgd51jsRI0UgD
x38BqiT/LSxlBtj+35tD/IVRgWwxsqAIiKUMbUgCLwFnQe2ADoUr5ceA+WE8V6iV
RodE4gZqZsxONO27XoZqu7LEfi4Xa53qpo0v+OEqk0OsrBMeuRqOVn770Qj6Osoy
jOvqiMwBAoGBAOwsg8WLwWJGMjcUDxIPqxKFIH3OKLEUohztwf5GgSq6ZXOpF8Ib
rmLgMWERPYdS17UipWMlQTcHYywSX/dH2yEKdN+98TPaovb0q3rr2+011cxH5t3F
YYF+C8eakhmBElogORyaAWSq4/F4vO+UHP6xC+ZfYOcEnpIX0QIiySoBAoGBAMVY
VvKd6DKBlY9AwnXEM+r04kvX7oyh8WsufPWY5J4o8LXm9SofD0hLp5OBNoK6NNEs
pi72s6CXfJ0iNYgkl3FHq1+iHnPcB6uyosyEfROmZTzSnuLMiGsOSEc0MDHnAm8L
KUvRu/k2wp+Q36R1dAB2S2MkxgIYcu2D2wENKBPXAoGBAJCiJkSpdNHBWWk/oIcY
D1U1MBO7WFIx56G9vUsCVIIdSpoNWN5n42DsGXFvhHXGNxHX2N8h5pFTtdk8m4at
e7X9WFvZT8jIwXpplkaeAL6BdKA4/FqeUTtjPMWNlKGH2PxWtYMdkXLb8OJlZZd2
5lbXiAkaKhbwTkf7y+T59qYBAoGAFfg/tcLelsDWZZxQCcxN+1pH1ymy5PUia0xB
nRXoXbMxGQ8dPBM5IFNL1KAN8X/JYYAXACN22+oBdXzZeM6aDYJtEbh6q2tTb0nz
1dDqG8Xqf1rzVUxv43szkLm+o8+T9cjIUCiJRLVT9W+rdiOdRm/k9KSjZphSMx76
wqM0UwECgYBmaCJ9yNlS0WSju0lV3YOlRXCXyilPrFoLakEaoW8cuGqgn3R2YPcm
TA5tHGZhx6g+jBVtwhq/ezGaNQ7PA7kTLth1bYLD/v7rga+zfUWhNmkwfN4NtFM8
ntFiDOMPUkVwYD7iVjrJsS0XQwa2rfsPEtCWbniqU5QG47QJpORyvQ==
-----END RSA PRIVATE KEY-----
";

static GOOD_SNI: &'static str = "app1.customer1.socket.ebbflow.io";
