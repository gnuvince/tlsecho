#[macro_use] extern crate log;
extern crate env_logger;
extern crate clap;
extern crate rustls;
extern crate webpki;

use clap::{App, Arg, ArgMatches, SubCommand};
use rustls::Session;
use std::error::Error;
use std::fs;
use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

type Result<T> = ::std::result::Result<T, Box<dyn Error>>;

// XXX: use "localhost", because it's a DNS name specified in the certificates.
const BIND: &str = "localhost:9999";
const PAYLOAD: &[u8] = b"I AM A TLS PACKET";

fn main() {
    env_logger::init();
    let app = App::new("tlsecho")
        .subcommand(SubCommand::with_name("server")
                    .arg(Arg::with_name("cert")
                         .long("--cert")
                         .takes_value(true)
                         .required(true))
                    .arg(Arg::with_name("privkey")
                         .long("-privkey")
                         .takes_value(true)
                         .required(true))
        )
        .subcommand(SubCommand::with_name("client")
                    .arg(Arg::with_name("ca")
                         .long("--ca")
                         .takes_value(true)
                         .required(true))
        );
    let matches = app.get_matches();

    match matches.subcommand() {
        ("server", Some(args)) => handle_error(server(args)),
        ("client", Some(args)) => handle_error(client(args)),
        (_, _) => unreachable!()
    }
}

fn server(matches: &ArgMatches) -> Result<()> {
    // Load the TLS certificates from disk.
    let certs = {
        let cert_file = matches.value_of("cert").unwrap();
        // XXX: rustc has difficulty with type inference if I use .map_err()
        rustls::internal::pemfile::certs(&mut BufReader::new(
            fs::File::open(cert_file)?
        )).expect("could not load certificates")
    };

    // Load the TLS private key from disk.
    let privkeys = {
        let privkey_file = matches.value_of("privkey").unwrap();
        // XXX: rustc has difficulty with type inference if I use .map_err()
        rustls::internal::pemfile::rsa_private_keys(&mut BufReader::new(
            fs::File::open(privkey_file)?
        )).expect("could not load private keys")
    };

    // Create a TLS server configuration that does not verify clients,
    // i.e., the client doesn't have to send its own certificate.
    let tls_server_config = {
        let verifier = rustls::NoClientAuth::new();
        let mut config = rustls::ServerConfig::new(verifier);
        config.set_single_cert(certs, privkeys[0].clone())?;
        Arc::new(config)
    };

    // Create a TLS server session.
    let mut tls_server = rustls::ServerSession::new(&tls_server_config);

    // Listen for TCP connections.
    let listener = TcpListener::bind(BIND)?;

    // Handle incoming connections.
    for stream in listener.incoming() {
        let mut stream = stream?;
        info!("server: accepted connection from {:?}", stream.peer_addr()?);
        finish_tls_handshake(&mut tls_server, &mut stream)?;
        info!("server: finished TLS handshake");

        tls_server.read_tls(&mut stream)?;
        tls_server.process_new_packets()?;
        let mut plaintext = String::new();
        let n = tls_server.read_to_string(&mut plaintext)?;
        info!("server: read {} bytes: {:?}", n, plaintext);

        break;
    }

    return Ok(());
}

fn client(matches: &ArgMatches) -> Result<()> {
    // Create a TLS client configuration and add the certificate of
    // the CA to the configuration's root certificate store.
    let tls_client_config = {
        let ca_file = matches.value_of("ca").unwrap();
        let mut config = rustls::ClientConfig::new();
        config.root_store.add_pem_file(&mut BufReader::new(
            fs::File::open(ca_file)?)
        ).expect("could not add CA");
        Arc::new(config)
    };

    // Create a TLS client session.
    let localhost_dns = webpki::DNSNameRef::try_from_ascii_str("localhost").expect("dns");
    let mut tls_client = rustls::ClientSession::new(&tls_client_config, localhost_dns);

    // Open a TCP connection to the server.
    let mut stream = TcpStream::connect(BIND)?;

    // This part I don't quite understand:
    // 1. Write the payload to the TLS client,
    // 2. Send the encrypted payload over TCP,
    // 3. Since there was not a session established between
    //    the client and the server yet, they will perform a
    //    handshake and once that's finished, the payload will
    //    be received by the server.
    tls_client.write(PAYLOAD)?;
    tls_client.write_tls(&mut stream)?;
    finish_tls_handshake(&mut tls_client, &mut stream)?;

    info!("client: finished TLS handshake");

    return Ok(());
}


/// Display an error to `stderr` and exit.
fn handle_error<T>(res: Result<T>) {
    if let Err(e) = res {
        error!("tlsecho: {}", e);
        ::std::process::exit(1);
    }
}

/// Send packets back and forth until handshake is finished.
/// If the handshake take more than `MAX_ITERS` iterations, bail out.
fn finish_tls_handshake<S: Session>(session: &mut S, stream: &mut TcpStream) -> Result<()> {
    const MAX_ITERS: i32 = 32;
    let mut iters = MAX_ITERS;
    while session.is_handshaking() {
        if iters == 0 {
            let err = format!("finish_tls_handshake took more than {} iterations, bailing out.", MAX_ITERS);
            return Err(err.into());
        }

        if session.wants_read() {
            trace!("wants read");
            session.read_tls(stream)?;
            session.process_new_packets()?;
        }

        while session.wants_write() {
            trace!("wants write");
            session.write_tls(stream)?;
        }

        iters -= 1;
    }
    return Ok(());
}
