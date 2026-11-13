//! Before the client sends a credential (an invitation, a bearer token) to a plain-http loopback server, it checks that
//! the listening socket belongs to the same OS user (P1). On a shared machine another user could otherwise bind the
//! local-mode port while Dove is not running and collect tokens: plain HTTP authenticates nobody. HTTPS servers are
//! authenticated by TLS and are not checked.
//!
//! Linux reads the owner uid of listening sockets from `/proc/net/tcp{,6}`; Windows maps the listener's owning PID
//! (`GetExtendedTcpTable`) to its user SID. Other platforms (macOS) cannot attribute a listener to a user without
//! walking every process, so the check is skipped there (documented residual risk, docs/deployment.md). A small
//! window between the check and the connection remains on every platform.

use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{anyhow, bail};

/// Checks `server` (a normalized origin) before a credential is sent to it. A no-op unless it is plain http on a
/// loopback host.
pub fn check_server(server: &str) -> anyhow::Result<()> {
    let Some(targets) = loopback_targets(server)? else {
        return Ok(());
    };
    check_targets(&targets).map_err(|why| {
        anyhow!(
            "refusing to send credentials to {server}: {why}. Start your own Dove (`dove local start`) and try again"
        )
    })
}

/// The socket addresses a plain-http loopback origin connects to; `None` for anything else.
fn loopback_targets(server: &str) -> anyhow::Result<Option<Vec<SocketAddr>>> {
    let u = url::Url::parse(server).map_err(|_| anyhow!("invalid server URL {server}"))?;
    if u.scheme() != "http" {
        return Ok(None);
    }
    let Some(port) = u.port_or_known_default() else { bail!("invalid server URL {server}") };
    let ips: Vec<IpAddr> = match u.host() {
        Some(url::Host::Ipv4(ip)) if ip.is_loopback() => vec![ip.into()],
        Some(url::Host::Ipv6(ip)) if ip.is_loopback() => vec![ip.into()],
        Some(url::Host::Domain("localhost")) => vec![Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()],
        _ => return Ok(None),
    };
    Ok(Some(ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect()))
}

/// Whether a listener bound to `listener` receives connections made to `target`.
fn serves(listener: SocketAddr, target: SocketAddr) -> bool {
    if listener.port() != target.port() {
        return false;
    }
    match (listener.ip(), target.ip()) {
        (l, t) if l == t => true,
        (IpAddr::V4(l), IpAddr::V4(_)) => l.is_unspecified(),
        // A dual-stack `::` listener also takes IPv4 connections; `::ffff:a.b.c.d` is that IPv4 address.
        (IpAddr::V6(l), IpAddr::V4(t)) => l.is_unspecified() || l.to_ipv4_mapped() == Some(t),
        (IpAddr::V6(l), IpAddr::V6(_)) => l.is_unspecified(),
        (IpAddr::V4(_), IpAddr::V6(_)) => false,
    }
}

/// The decision, kept pure for tests: every listener that could take a connection to one of `targets` must belong to
/// `me`, and at least one must exist.
pub fn listeners_ok<O: PartialEq + Debug>(
    targets: &[SocketAddr],
    listeners: &[(SocketAddr, O)],
    me: &O,
) -> Result<(), String> {
    let relevant: Vec<&(SocketAddr, O)> =
        listeners.iter().filter(|(l, _)| targets.iter().any(|t| serves(*l, *t))).collect();
    if relevant.is_empty() {
        return Err("nothing listens there".into());
    }
    if let Some((l, owner)) = relevant.iter().find(|(_, o)| o != me) {
        return Err(format!("the listener on {l} belongs to another user ({owner:?})"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn check_targets(targets: &[SocketAddr]) -> Result<(), String> {
    let mut listeners = Vec::new();
    for (file, v6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        match std::fs::read_to_string(file) {
            Ok(text) => listeners.extend(linux::listening(&text, v6)),
            // No IPv6 in this kernel: nothing can listen there.
            Err(e) if v6 && e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("cannot read {file} ({e})")),
        }
    }
    listeners_ok(targets, &listeners, &nix::unistd::getuid().as_raw())
}

#[cfg(windows)]
fn check_targets(targets: &[SocketAddr]) -> Result<(), String> {
    use crate::platform::windows as win;
    let me = win::current_user_sid().map_err(|e| format!("cannot read this user's SID ({e})"))?;
    let mut listeners = Vec::new();
    for (addr, pid) in win::tcp_listeners().map_err(|e| format!("cannot list TCP listeners ({e})"))? {
        // A process this user cannot open (another user's, or a protected one) is not ours.
        let owner = win::process_user_sid(pid).ok().and_then(|s| s.to_string_sid().ok());
        listeners.push((addr, owner.unwrap_or_else(|| format!("pid {pid}"))));
    }
    let me = me.to_string_sid().map_err(|e| e.to_string())?;
    listeners_ok(targets, &listeners, &me)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn check_targets(_targets: &[SocketAddr]) -> Result<(), String> {
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
mod linux {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    /// `TCP_LISTEN` in the `st` column.
    const LISTEN: &str = "0A";

    /// Listening sockets and their owner uid from the text of `/proc/net/tcp` (`v6` false) or `/proc/net/tcp6`.
    /// Addresses are the kernel's network-order bytes printed as native-endian 32-bit words.
    pub fn listening(text: &str, v6: bool) -> Vec<(SocketAddr, u32)> {
        text.lines().skip(1).filter_map(|line| parse_line(line, v6)).collect()
    }

    fn parse_line(line: &str, v6: bool) -> Option<(SocketAddr, u32)> {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.get(3) != Some(&LISTEN) {
            return None;
        }
        let (addr, port) = f.get(1)?.split_once(':')?;
        let port = u16::from_str_radix(port, 16).ok()?;
        let word = |s: &str| u32::from_str_radix(s, 16).ok().map(u32::to_ne_bytes);
        let ip: IpAddr = if v6 {
            if addr.len() != 32 {
                return None;
            }
            let mut b = [0u8; 16];
            for i in 0..4 {
                b[i * 4..i * 4 + 4].copy_from_slice(&word(addr.get(i * 8..i * 8 + 8)?)?);
            }
            Ipv6Addr::from(b).into()
        } else {
            if addr.len() != 8 {
                return None;
            }
            Ipv4Addr::from(word(addr)?).into()
        };
        let uid = f.get(7)?.parse().ok()?;
        Some((SocketAddr::new(ip, port), uid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn only_plain_http_loopback_servers_are_checked() {
        assert_eq!(loopback_targets("https://dove.example.com").unwrap(), None);
        assert_eq!(loopback_targets("https://127.0.0.1:8443").unwrap(), None);
        assert_eq!(loopback_targets("http://127.0.0.1:8765").unwrap(), Some(vec![sa("127.0.0.1:8765")]));
        assert_eq!(loopback_targets("http://[::1]:8765").unwrap(), Some(vec![sa("[::1]:8765")]));
        assert_eq!(
            loopback_targets("http://localhost:8765").unwrap(),
            Some(vec![sa("127.0.0.1:8765"), sa("[::1]:8765")])
        );
    }

    /// The decision: every listener that would take the connection is ours, and there is one.
    #[test]
    fn every_listener_that_could_answer_must_be_ours() {
        let t = [sa("127.0.0.1:8765")];
        assert!(listeners_ok(&t, &[(sa("127.0.0.1:8765"), 1000)], &1000).is_ok());
        assert!(listeners_ok(&t, &[(sa("0.0.0.0:8765"), 1000)], &1000).is_ok());
        assert!(listeners_ok(&t, &[(sa("[::]:8765"), 1000)], &1000).is_ok());
        let other = listeners_ok(&t, &[(sa("127.0.0.1:8765"), 1001)], &1000).unwrap_err();
        assert!(other.contains("another user"), "{other}");
        // A wildcard or dual-stack listener of another user on the same port could take the connection.
        assert!(listeners_ok(&t, &[(sa("127.0.0.1:8765"), 1000), (sa("0.0.0.0:8765"), 1001)], &1000).is_err());
        assert!(listeners_ok(&t, &[(sa("127.0.0.1:8765"), 1000), (sa("[::]:8765"), 1001)], &1000).is_err());
        assert!(listeners_ok(&t, &[(sa("[::ffff:127.0.0.1]:8765"), 1001)], &1000).is_err());
        // Other ports, other addresses and IPv4 wildcards for an IPv6 target do not count.
        let unrelated = [(sa("127.0.0.1:8766"), 1001), (sa("127.0.0.2:8765"), 1001), (sa("[::1]:8765"), 1001)];
        assert!(listeners_ok(&t, &unrelated, &1000).unwrap_err().contains("nothing listens"));
        assert!(listeners_ok(&[sa("[::1]:8765")], &[(sa("0.0.0.0:8765"), 1001)], &1000).is_err());
        assert!(
            listeners_ok(&[sa("[::1]:8765")], &[(sa("[::1]:8765"), 1000), (sa("0.0.0.0:8765"), 1001)], &1000).is_ok()
        );
        // localhost: both addresses count.
        let both = [sa("127.0.0.1:8765"), sa("[::1]:8765")];
        assert!(listeners_ok(&both, &[(sa("127.0.0.1:8765"), 1000), (sa("[::1]:8765"), 1001)], &1000).is_err());
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn proc_net_tcp_is_parsed() {
        let v4 = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:2231 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2345 1 0000000000000000 100 0 0 10 0
   2: 0100007F:2231 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1001        0 3456 1 0000000000000000 20 4 30 10 -1
";
        assert_eq!(linux::listening(v4, false), vec![(sa("127.0.0.1:8753"), 1000), (sa("0.0.0.0:22"), 0)]);
        let v6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:2231 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 4567 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5678 1 0000000000000000 100 0 0 10 0
   2: 0000000000000000FFFF00000100007F:2231 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1002        0 6789 1 0000000000000000 100 0 0 10 0
";
        assert_eq!(
            linux::listening(v6, true),
            vec![(sa("[::1]:8753"), 1001), (sa("[::]:22"), 0), (sa("[::ffff:127.0.0.1]:8753"), 1002)]
        );
    }

    /// The real tables: a listener this process opens is attributed to this user, and nothing else on its port is.
    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn own_listener_passes_the_check() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        check_server(&format!("http://127.0.0.1:{port}")).unwrap();
        drop(l);
        let err = check_server(&format!("http://127.0.0.1:{port}")).unwrap_err().to_string();
        assert!(err.contains("nothing listens"), "{err}");
        check_server("https://dove.example.com").unwrap();
    }
}
