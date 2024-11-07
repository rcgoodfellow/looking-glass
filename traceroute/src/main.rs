#![feature(maybe_uninit_slice)]

use clap::Parser;
use colored::Colorize;
use ispf::to_bytes_be;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{
    Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs,
};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Traceroute
#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    /// Host to trace.
    #[clap(value_parser)]
    host: String,

    #[clap(long, default_value = "arin")]
    region: String
}

#[derive(Debug, Serialize, Deserialize)]
struct EchoRequest {
    typ: u8,
    code: u8,
    checksum: u16,
    identifier: u16,
    sequence_number: u16,
}

fn main() {
    let args = Args::parse();

    let host = format!("{}:0", args.host);
    let sa: SockAddr = host.to_socket_addrs().unwrap().next().unwrap().into();

    if let Some(s4) = sa.as_socket_ipv4() {
        run4(s4.ip(), &args.region);
    }
    if let Some(s6) = sa.as_socket_ipv6() {
        run6(s6.ip(), &args.region);
    }
}

fn run4(addr: &Ipv4Addr, region: &str) {
    println!("{} {}", "->".dimmed(), addr.to_string().blue());
    for i in 0..255 {
        if ping4(addr, i, &region) {
            break;
        }
    }
}

fn run6(addr: &Ipv6Addr, region: &str) {
    println!("{} {}", "->".dimmed(), addr.to_string().blue());
    for i in 0..64 {
        if ping6(addr, i, &region) {
            break;
        }
    }
}

fn ping6(dst: &Ipv6Addr, i: u16, region: &str) -> bool {
    let sa: SockAddr = SocketAddrV6::new(*dst, 0, 0, 0).into();

    let pkt = EchoRequest {
        typ: 128,
        code: 0,
        checksum: 0,
        identifier: 47,
        sequence_number: i,
    };
    let msg = to_bytes_be(&pkt).unwrap();

    let t0 = Instant::now();
    let sock =
        Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).unwrap();
    sock.set_unicast_hops_v6((i + 1) as u32).unwrap();
    sock.send_to(&msg, &sa).unwrap();

    let mut ubuf = [MaybeUninit::new(0); 10240];

    sock.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    match sock.recv_from(&mut ubuf) {
        Ok((_, sndr)) => {
            let t1 = Instant::now();

            let s6 = sndr.as_socket_ipv6().unwrap();
            let remote = s6.ip();
            println!(
                "{} {} {} {} {}",
                i.to_string().dimmed(),
                remote.to_string().cyan(),
                ((t1 - t0).as_micros() as f32 / 1000.0)
                    .to_string()
                    .magenta(),
                "ms".dimmed(),
                who(remote.to_string(), region),
            );


            if remote == dst {
                return true;
            }
        }
        Err(_) => {
            println!("{} {}", i.to_string().dimmed(), "*".dimmed());
        }
    }

    sleep(Duration::from_millis(25));

    false
}

fn ping4(dst: &Ipv4Addr, i: u16, region: &str) -> bool {
    let sa: SockAddr = SocketAddrV4::new(*dst, 0).into();

    let mut csum = p4rs::checksum::Csum::default();
    csum.add(
        8u8, // type
        0u8, // code
    );
    csum.add16(47u16.to_be_bytes()); // identifier
    csum.add16(i.to_be_bytes()); // sequence number

    let pkt = EchoRequest {
        typ: 8,
        code: 0,
        checksum: csum.result(),
        identifier: 47,
        sequence_number: i,
    };
    let msg = to_bytes_be(&pkt).unwrap();

    let t0 = Instant::now();
    let sock =
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).unwrap();
    sock.set_ttl((i + 1) as u32).unwrap();
    sock.send_to(&msg, &sa).unwrap();

    let mut ubuf = [MaybeUninit::new(0); 10240];
    sock.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    match sock.recv_from(&mut ubuf) {
        Ok((_, sndr)) => {
            let t1 = Instant::now();

            let s4 = sndr.as_socket_ipv4().unwrap();
            let remote = s4.ip();
            println!(
                "{} {} {} {} {}",
                i.to_string().dimmed(),
                remote.to_string().cyan(),
                ((t1 - t0).as_micros() as f32 / 1000.0)
                    .to_string()
                    .magenta(),
                "ms".dimmed(),
                who(remote.to_string(), region),
            );


            if remote == dst {
                return true;
            }
        }
        Err(_) => {
            println!("{} {}", i.to_string().dimmed(), "*".dimmed());
        }
    }

    sleep(Duration::from_millis(25));

    return false;
}

fn who(addr: String, region: &str) -> String {
    let sock = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    let sa = {
        let mut addrs = format!("whois.{}.net:43", region).to_socket_addrs().unwrap();
        addrs.find(|x| matches!(x, SocketAddr::V4(_))).unwrap()
    };
    let sa: SockAddr = sa.into();
    sock.connect(&sa).unwrap();

    let addr = format!("n + {}\r\n", addr);
    sock.send_to(addr.as_bytes(), &sa).unwrap();
    let mut s = String::new();
    loop {
        let mut ubuf = [MaybeUninit::new(0); 10240];
        match sock.recv_from(&mut ubuf) {
            Ok((sz, _)) => {
                if sz == 0 {
                    break;
                }
                let buf = unsafe { &MaybeUninit::slice_assume_init_ref(&ubuf) };
                let msg = String::from_utf8_lossy(&buf[..sz]);
                let lines = msg.lines();
                for l in lines {
                    if let Some(x) = l.strip_prefix("OriginAS:") {
                        let x = x.trim();
                        if !x.is_empty() {
                            s += &format!(" {}", x.blue());
                        }
                    }
                    if let Some(x) = l.strip_prefix("Organization:") {
                        let x = x.trim();
                        if !x.is_empty() {
                            s += &format!(" {}", x);
                            break;
                        }
                    }
                }
            }
            Err(_) => {
                break;
            }
        }
    }
    s
}
