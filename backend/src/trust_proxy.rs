//! `trust proxy` semantics of Express (`proxy-addr`): resolves the client IP from the socket
//! address and the `X-Forwarded-For` chain.

use std::net::{IpAddr, Ipv6Addr};

use ipnet::IpNet;

#[derive(Debug, Clone)]
pub enum TrustProxy {
    All,
    None,
    Hops(usize),
    Subnets(Vec<IpNet>),
}

fn preset(name: &str) -> Option<&'static [&'static str]> {
    match name {
        "loopback" => Some(&["127.0.0.1/8", "::1/128"]),
        "linklocal" => Some(&["169.254.0.0/16", "fe80::/10"]),
        "uniquelocal" => Some(&["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]),
        _ => None,
    }
}

impl TrustProxy {
    pub fn parse(value: &str) -> Result<Self, String> {
        let value = value.trim();
        match value {
            "true" => return Ok(Self::All),
            "false" => return Ok(Self::None),
            _ => {}
        }
        if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
            return value
                .parse::<usize>()
                .map(Self::Hops)
                .map_err(|e| e.to_string());
        }

        let mut nets = Vec::new();
        for entry in value.split(',').map(str::trim) {
            if let Some(cidrs) = preset(entry) {
                nets.extend(
                    cidrs
                        .iter()
                        .map(|c| c.parse::<IpNet>().expect("static CIDR")),
                );
                continue;
            }
            let net = if entry.contains('/') {
                entry
                    .parse::<IpNet>()
                    .map_err(|_| format!("invalid subnet '{entry}'"))?
            } else {
                let ip = entry
                    .parse::<IpAddr>()
                    .map_err(|_| format!("invalid IP address or preset '{entry}'"))?;
                IpNet::from(ip)
            };
            nets.push(net);
        }
        Ok(Self::Subnets(nets))
    }

    fn trusts(&self, addr: &str, hop: usize) -> bool {
        match self {
            Self::All => true,
            Self::None => false,
            Self::Hops(n) => hop < *n,
            Self::Subnets(nets) => {
                let Ok(ip) = addr.parse::<IpAddr>() else {
                    return false;
                };
                let ip = unmap(ip);
                nets.iter().any(|net| net.contains(&ip))
            }
        }
    }

    /// `proxyaddr(req, trust)`: walk the chain `[socket, xff[n-1], .., xff[0]]` while hops are trusted.
    pub fn resolve(&self, socket_addr: &str, x_forwarded_for: Option<&str>) -> String {
        let mut addrs: Vec<String> = vec![socket_addr.to_string()];
        if let Some(xff) = x_forwarded_for {
            addrs.extend(xff.split(',').map(|s| s.trim().to_string()).rev());
        }

        let mut end = addrs.len();
        for (i, addr) in addrs.iter().enumerate().take(addrs.len() - 1) {
            if !self.trusts(addr, i) {
                end = i + 1;
                break;
            }
        }
        addrs.swap_remove(end - 1)
    }
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6_to_v4(v6).map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

fn v6_to_v4(v6: Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    v6.to_ipv4_mapped()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hops_pick_the_nth_address_from_the_right() {
        let tp = TrustProxy::parse("1").unwrap();
        assert_eq!(tp.resolve("10.0.0.1", Some("1.2.3.4, 5.6.7.8")), "5.6.7.8");
        let tp = TrustProxy::parse("2").unwrap();
        assert_eq!(tp.resolve("10.0.0.1", Some("1.2.3.4, 5.6.7.8")), "1.2.3.4");
        let tp = TrustProxy::parse("0").unwrap();
        assert_eq!(tp.resolve("10.0.0.1", Some("1.2.3.4")), "10.0.0.1");
    }

    #[test]
    fn spoofed_xff_is_ignored_when_proxy_is_untrusted() {
        let tp = TrustProxy::parse("false").unwrap();
        assert_eq!(tp.resolve("9.9.9.9", Some("1.1.1.1")), "9.9.9.9");
        let tp = TrustProxy::parse("loopback").unwrap();
        assert_eq!(tp.resolve("9.9.9.9", Some("1.1.1.1")), "9.9.9.9");
        assert_eq!(tp.resolve("127.0.0.1", Some("1.1.1.1")), "1.1.1.1");
        assert_eq!(tp.resolve("::ffff:127.0.0.1", Some("1.1.1.1")), "1.1.1.1");
    }

    #[test]
    fn trust_all_uses_leftmost_entry() {
        let tp = TrustProxy::parse("true").unwrap();
        assert_eq!(tp.resolve("10.0.0.1", Some("1.1.1.1, 2.2.2.2")), "1.1.1.1");
    }

    #[test]
    fn subnet_list_stops_at_first_untrusted_hop() {
        let tp = TrustProxy::parse("172.16.0.0/12, 10.1.1.1").unwrap();
        assert_eq!(
            tp.resolve("172.18.0.2", Some("8.8.8.8, 10.1.1.1")),
            "8.8.8.8"
        );
        assert_eq!(
            tp.resolve("172.18.0.2", Some("7.7.7.7, 8.8.8.8")),
            "8.8.8.8"
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(TrustProxy::parse("nonsense").is_err());
        assert!(TrustProxy::parse("10.0.0.0/99").is_err());
    }
}
