//! Hub 地址：`https://<host>[:<port>]`，路径部分不用。

use rustls::pki_types::ServerName;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubUrl {
    pub host: String,
    pub port: u16,
}

impl HubUrl {
    pub fn parse(url: &str) -> Result<Self, String> {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| format!("{url}: the Hub address must start with https://"))?;
        let authority = rest.split('/').next().unwrap_or_default();
        if authority.is_empty() || authority.contains('@') {
            return Err(format!("{url}: not a Hub address"));
        }
        // [IPv6]:port、host:port、host
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (h, after) = v6
                .split_once(']')
                .ok_or_else(|| format!("{url}: bad IPv6 address"))?;
            let port = after
                .strip_prefix(':')
                .map(str::parse)
                .transpose()
                .map_err(|_| format!("{url}: bad port"))?;
            (h.to_owned(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (
                    h.to_owned(),
                    Some(p.parse().map_err(|_| format!("{url}: bad port"))?),
                ),
                None => (authority.to_owned(), None),
            }
        };
        Ok(Self {
            host,
            port: port.unwrap_or(443),
        })
    }

    pub fn server_name(&self) -> Result<ServerName<'static>, String> {
        ServerName::try_from(self.host.clone()).map_err(|e| format!("{}: {e}", self.host))
    }

    /// HTTP 的 `Host`：默认端口时省略端口。
    pub fn host_header(&self) -> String {
        if self.port == 443 {
            if self.host.contains(':') {
                format!("[{}]", self.host)
            } else {
                self.host.clone()
            }
        } else {
            self.authority()
        }
    }

    /// `host:port`，IPv6 加方括号。
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hub_addresses_parse() {
        let u = HubUrl::parse("https://hub.example.com").expect("ok");
        assert_eq!((u.host.as_str(), u.port), ("hub.example.com", 443));
        let u = HubUrl::parse("https://192.0.2.1:8443/x").expect("ok");
        assert_eq!((u.host.as_str(), u.port), ("192.0.2.1", 8443));
        assert_eq!(u.authority(), "192.0.2.1:8443");
        assert_eq!(u.host_header(), "192.0.2.1:8443");
        assert_eq!(
            HubUrl::parse("https://hub.example.com/")
                .expect("ok")
                .host_header(),
            "hub.example.com"
        );
        let u = HubUrl::parse("https://[2001:db8::1]:9443").expect("ok");
        assert_eq!(u.authority(), "[2001:db8::1]:9443");
        for bad in [
            "http://hub.example.com",
            "https://",
            "https://u@h",
            "https://h:x",
        ] {
            assert!(HubUrl::parse(bad).is_err(), "{bad}");
        }
    }
}
