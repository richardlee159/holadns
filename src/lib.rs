mod config;
mod protocol;

use config::Config;
use protocol::*;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};

pub type UniResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
enum ReMod {
    Intercept,
    Local,
    Relay,
}

pub fn run_server() -> UniResult<()> {
    let config = Config::new();
    let rule_table = read_rule(&config.rule_file)?;

    let listen_socket = UdpSocket::bind(&config.listen_addr)?;

    let rule_table = Arc::new(rule_table);
    let remote_addr = Arc::new(config.remote_addr);

    loop {
        let mut req_buf = [0; 512];

        let (recv_len, req_addr) = listen_socket.recv_from(&mut req_buf)?;

        let listen_socket = listen_socket.try_clone()?;
        let rule_table = Arc::clone(&rule_table);
        let remote_addr = Arc::clone(&remote_addr);

        thread::spawn(move || {
            let recv_time = SystemTime::now();

            let req_buf = &req_buf[..recv_len];
            let request = DnsPacket::from(req_buf).unwrap();
            let qname = request.questions[0].qname.to_string();

            let resolve_mode: ReMod;
            let mut resp_buf = [0; 512];
            let send_len = match rule_table.get(&qname) {
                Some(&ipaddr) => {
                    let mut response = request;
                    response.header.qr = true;
                    response.header.aa = false;
                    response.header.tc = false;
                    response.header.ra = true;
                    if ipaddr == Ipv4Addr::UNSPECIFIED {
                        resolve_mode = ReMod::Intercept;
                        response.header.rcode = 3;
                    } else {
                        resolve_mode = ReMod::Local;
                        response.header.rcode = 0;
                        response.header.ancount = 1;
                        response.answers.push(DnsRecord::A {
                            name: qname.clone(),
                            addr: ipaddr,
                            ttl: 100,
                        });
                    };
                    response.write(&mut resp_buf).unwrap()
                }
                None => {
                    resolve_mode = ReMod::Relay;
                    let lookup_socket = UdpSocket::bind("0.0.0.0:0").unwrap();
                    lookup_socket
                        .set_read_timeout(Some(Duration::from_secs(10)))
                        .unwrap();
                    lookup_socket.connect(&remote_addr[..]).unwrap();
                    lookup_socket.send(req_buf).unwrap();
                    match lookup_socket.recv(&mut resp_buf) {
                        Ok(len) => len,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            eprintln!("Request {} timeout", qname);
                            return;
                        }
                        Err(e) => panic!("{}", e),
                    }
                }
            };

            listen_socket.send_to(&resp_buf[..send_len], req_addr).unwrap();
            println!(
                "Handle {} in {} ms. Mode: {:?}",
                qname,
                recv_time.elapsed().unwrap().as_millis(),
                resolve_mode
            );
        });
    }
}

type RuleTable = HashMap<String, Ipv4Addr>;

fn read_rule(filename: &str) -> UniResult<RuleTable> {
    let mut dnstable = HashMap::new();

    let config = fs::read_to_string(filename)?;

    for line in config.lines() {
        if line.is_empty() {
            continue;
        }

        let conf: Vec<&str> = line.split(' ').collect();
        if conf.len() != 2 {
            return Err("Rule file format error".into());
        }
        let ipaddr = conf[0].parse()?;
        let name = conf[1].to_owned();
        dnstable.insert(name, ipaddr);
    }

    Ok(dnstable)
}
