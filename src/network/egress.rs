use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::net::lookup_host;
use tokio::time::timeout;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressBlockReason {
    Localhost { host: String },
    NonGlobalIpLiteral { ip: IpAddr },
    NonGlobalDns { host: String, ips: Vec<IpAddr> },
}

#[derive(Debug, Clone)]
struct HostCacheEntry {
    checked_at: Instant,
    ips: Vec<IpAddr>,
    any_non_global: bool,
}

#[derive(Debug)]
pub struct EgressBlocker {
    cache: DashMap<String, HostCacheEntry>,
    cache_ttl: Duration,
    dns_timeout: Duration,
}

impl EgressBlocker {
    pub fn new(dns_timeout: Duration, cache_ttl: Duration) -> Self {
        Self {
            cache: DashMap::new(),
            cache_ttl,
            dns_timeout,
        }
    }

    pub async fn check_url(&self, raw_url: &str) -> Option<EgressBlockReason> {
        let url = Url::parse(raw_url).ok()?;
        self.check_parsed_url(&url).await
    }

    pub async fn check_parsed_url(&self, url: &Url) -> Option<EgressBlockReason> {
        match url.scheme() {
            "http" | "https" | "ws" | "wss" => {}
            // Non-network URLs are not an egress concern here.
            _ => return None,
        }

        let host = url.host_str()?.trim();
        if host.is_empty() {
            return None;
        }

        if is_localhost_host(host) {
            return Some(EgressBlockReason::Localhost {
                host: host.to_string(),
            });
        }

        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_non_global_ip(ip) {
                return Some(EgressBlockReason::NonGlobalIpLiteral { ip });
            }
            return None;
        }

        let host_key = host.to_ascii_lowercase();
        if let Some(entry) = self.cache.get(&host_key) {
            if entry.checked_at.elapsed() <= self.cache_ttl {
                if entry.any_non_global {
                    return Some(EgressBlockReason::NonGlobalDns {
                        host: host.to_string(),
                        ips: entry.ips.clone(),
                    });
                }
                return None;
            }
        }

        let port = url.port_or_known_default().unwrap_or(80);
        let ips = resolve_ips(host, port, self.dns_timeout).await;
        let Some(ips) = ips else {
            // If we can't resolve, Chrome will likely fail too. Allow to proceed.
            return None;
        };

        let any_non_global = ips.iter().copied().any(is_non_global_ip);
        self.cache.insert(
            host_key,
            HostCacheEntry {
                checked_at: Instant::now(),
                ips: ips.clone(),
                any_non_global,
            },
        );

        if any_non_global {
            return Some(EgressBlockReason::NonGlobalDns {
                host: host.to_string(),
                ips,
            });
        }

        None
    }
}

impl Default for EgressBlocker {
    fn default() -> Self {
        // Keep DNS timeouts short to avoid stalling scans on flaky third-party hosts.
        Self::new(Duration::from_secs(2), Duration::from_secs(60))
    }
}

fn is_localhost_host(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    h == "localhost" || h.ends_with(".localhost")
}

fn is_non_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_non_global_ipv4(v4),
        IpAddr::V6(v6) => is_non_global_ipv6(v6),
    }
}

fn is_non_global_ipv4(v4: Ipv4Addr) -> bool {
    if v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_documentation()
        || v4.is_broadcast()
        || v4.is_multicast()
    {
        return true;
    }

    let oct = v4.octets();

    // 0.0.0.0/8
    if oct[0] == 0 {
        return true;
    }

    // CGNAT 100.64.0.0/10
    if oct[0] == 100 && (64..=127).contains(&oct[1]) {
        return true;
    }

    // Benchmarking 198.18.0.0/15
    if oct[0] == 198 && (oct[1] == 18 || oct[1] == 19) {
        return true;
    }

    // IETF protocol assignments 192.0.0.0/24
    if oct[0] == 192 && oct[1] == 0 && oct[2] == 0 {
        return true;
    }

    // Reserved 240.0.0.0/4 (includes 255.255.255.255, handled above too).
    if oct[0] >= 240 {
        return true;
    }

    false
}

fn is_non_global_ipv6(v6: Ipv6Addr) -> bool {
    // Treat IPv4-mapped/compatible addresses via their v4 representation.
    if let Some(v4) = v6.to_ipv4() {
        return is_non_global_ipv4(v4);
    }

    if v6.is_loopback()
        || v6.is_unique_local()
        || v6.is_unicast_link_local()
        || v6.is_unspecified()
        || v6.is_multicast()
    {
        return true;
    }

    // Documentation 2001:db8::/32.
    let seg = v6.segments();
    if seg[0] == 0x2001 && seg[1] == 0x0db8 {
        return true;
    }

    false
}

async fn resolve_ips(host: &str, port: u16, dns_timeout: Duration) -> Option<Vec<IpAddr>> {
    let fut = lookup_host((host, port));
    let res = timeout(dns_timeout, fut).await.ok()?;
    let addrs = res.ok()?;
    let mut uniq: BTreeSet<IpAddr> = BTreeSet::new();
    for addr in addrs {
        uniq.insert(addr.ip());
    }
    Some(uniq.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn blocks_localhost() {
        let g = EgressBlocker::default();
        let reason = g.check_url("http://localhost:3000/").await;
        assert!(matches!(reason, Some(EgressBlockReason::Localhost { .. })));
    }

    #[tokio::test]
    async fn blocks_private_ip_literals() {
        let g = EgressBlocker::default();
        let reason = g.check_url("http://127.0.0.1:8080/").await;
        assert!(matches!(
            reason,
            Some(EgressBlockReason::NonGlobalIpLiteral { .. })
        ));
        let reason = g.check_url("http://10.0.0.1/").await;
        assert!(matches!(
            reason,
            Some(EgressBlockReason::NonGlobalIpLiteral { .. })
        ));
        let reason = g
            .check_url("http://169.254.169.254/latest/meta-data/")
            .await;
        assert!(matches!(
            reason,
            Some(EgressBlockReason::NonGlobalIpLiteral { .. })
        ));
    }

    #[tokio::test]
    async fn allows_global_ip_literals() {
        let g = EgressBlocker::default();
        let reason = g.check_url("https://1.1.1.1/").await;
        assert!(reason.is_none());
    }

    #[tokio::test]
    async fn ignores_non_network_schemes() {
        let g = EgressBlocker::default();
        assert!(g.check_url("data:text/plain,hi").await.is_none());
        assert!(g.check_url("blob:https://example.com/abc").await.is_none());
        assert!(g.check_url("about:blank").await.is_none());
    }
}
