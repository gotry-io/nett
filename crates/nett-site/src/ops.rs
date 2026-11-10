//! 修改站点的操作（design/site.md 第 4、5 节）。每个操作只改站点状态，不签名、不写文件；调用方随后签名、
//! 列出变化、确认、送达。操作在副本上进行，校验通过才替换：失败时站点状态不变。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nett_core::id::NodeId;
use nett_core::name::NodeName;
use nett_core::prefix::IpPrefix;
use nett_mesh::config::Reachability;
use nett_trust::payload::{MeshAddresses, PortRange};

use crate::SiteError;
use crate::state::{Edge, Machine, NodeKeys, Part, Revoked, Rule, RuleId, Selector, State};

/// 加入一台机器时的选项。
#[derive(Debug, Clone, Default)]
pub struct MachineOptions {
    pub public: bool,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    pub port: Option<u16>,
    pub keys: Option<NodeKeys>,
}

/// 修改一台机器时的选项：没写的项保持不变。
#[derive(Debug, Clone, Default)]
pub struct MachineChange {
    pub reachability: Option<Reachability>,
    pub ipv4: Option<Option<Ipv4Addr>>,
    pub ipv6: Option<Option<Ipv6Addr>>,
    pub port: Option<Option<u16>>,
}

impl State {
    /// 在副本上做一次修改，成功之后才替换：失败时站点状态不变。
    fn attempt<T>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<T, SiteError>,
    ) -> Result<T, SiteError> {
        let mut next = self.clone();
        let out = f(&mut next)?;
        *self = next;
        Ok(out)
    }

    pub fn add(
        &mut self,
        name: NodeName,
        opts: MachineOptions,
        node_id: NodeId,
    ) -> Result<(), SiteError> {
        self.attempt(|s| s.add_in(name, opts, node_id))
    }

    pub fn set(&mut self, name: &NodeName, change: MachineChange) -> Result<(), SiteError> {
        self.attempt(|s| s.set_in(name, change))
    }

    pub fn remove(&mut self, name: &NodeName) -> Result<(), SiteError> {
        self.attempt(|s| s.remove_in(name))
    }

    pub fn set_edge(
        &mut self,
        name: &NodeName,
        containers: Option<Vec<IpPrefix>>,
    ) -> Result<(), SiteError> {
        self.attempt(|s| s.set_edge_in(name, containers))
    }

    pub fn set_routes(&mut self, name: &NodeName, routes: Vec<IpPrefix>) -> Result<(), SiteError> {
        self.attempt(|s| s.set_routes_in(name, routes))
    }

    pub fn allow(
        &mut self,
        from: &[String],
        to: &[String],
        ports: Vec<PortRange>,
        note: Option<String>,
    ) -> Result<RuleId, SiteError> {
        self.attempt(|s| s.allow_in(from, to, ports, note))
    }

    pub fn remove_rule(&mut self, id: RuleId) -> Result<(), SiteError> {
        self.attempt(|s| s.remove_rule_in(id))
    }

    /// 加入一台机器：分配节点 ID 与组网地址。同一个名字以前被移除过时，这是一台新机器（design/site.md
    /// 第 4 节）。
    fn add_in(
        &mut self,
        name: NodeName,
        opts: MachineOptions,
        node_id: NodeId,
    ) -> Result<(), SiteError> {
        if self.machines.contains_key(&name) {
            return Err(SiteError::invalid(format!(
                "`{name}` is already in the site; `nett site set {name}` changes it"
            )));
        }
        if self.revoked.iter().any(|r| r.node_id == node_id) {
            return Err(SiteError::invalid("the new node ID was revoked before"));
        }
        let mesh = self.allocate()?;
        self.machines.insert(
            name,
            Machine {
                node_id,
                reachability: if opts.public {
                    Reachability::Public
                } else {
                    Reachability::DialOnly
                },
                ipv4: opts.ipv4,
                ipv6: opts.ipv6,
                port: opts.port,
                keys: opts.keys,
                mesh,
                edge: None,
                routes: Vec::new(),
                policy: None,
                routes_signed: None,
            },
        );
        self.check()
    }

    fn set_in(&mut self, name: &NodeName, change: MachineChange) -> Result<(), SiteError> {
        let m = self.machine_mut(name)?;
        if let Some(r) = change.reachability {
            m.reachability = r;
            if r == Reachability::DialOnly {
                m.ipv4 = None;
                m.ipv6 = None;
                m.port = None;
            }
        }
        if let Some(ipv4) = change.ipv4 {
            m.ipv4 = ipv4;
        }
        if let Some(ipv6) = change.ipv6 {
            m.ipv6 = ipv6;
        }
        if let Some(port) = change.port {
            m.port = port;
        }
        self.check()
    }

    /// 移除一台机器：生成身份撤销记录，规则中引用它的部分随之删除（design/site.md 第 4 节）。
    fn remove_in(&mut self, name: &NodeName) -> Result<(), SiteError> {
        let m = self
            .machines
            .remove(name)
            .ok_or_else(|| SiteError::invalid(format!("there is no machine `{name}`")))?;
        self.revoked.push(Revoked {
            name: name.clone(),
            node_id: m.node_id.clone(),
        });
        self.strip(|s| s.node == m.node_id);
        self.check()
    }

    /// 设置一台机器的 Edge 来源；`None` 去掉 Edge，引用它的规则随之清理。
    fn set_edge_in(
        &mut self,
        name: &NodeName,
        containers: Option<Vec<IpPrefix>>,
    ) -> Result<(), SiteError> {
        let node = self.machine(name)?.node_id.clone();
        match containers {
            Some(containers) => {
                let existing = self.machine(name)?.edge.as_ref().map(|e| e.addresses);
                let addresses = match existing {
                    Some(a) => a,
                    None => self.allocate()?,
                };
                self.machine_mut(name)?.edge = Some(Edge {
                    containers,
                    addresses,
                });
            }
            None => {
                self.machine_mut(name)?.edge = None;
                self.strip(|s| s.node == node && s.part == Part::Edge);
            }
        }
        self.check()
    }

    /// 设置一台机器宣告的网段；空的列表去掉宣告，引用它的规则随之清理。
    fn set_routes_in(&mut self, name: &NodeName, routes: Vec<IpPrefix>) -> Result<(), SiteError> {
        let node = self.machine(name)?.node_id.clone();
        let empty = routes.is_empty();
        self.machine_mut(name)?.routes = routes;
        if empty {
            self.strip(|s| s.node == node && s.part == Part::Routes);
        }
        self.check()
    }

    /// 加一条访问规则，返回它的编号。
    fn allow_in(
        &mut self,
        from: &[String],
        to: &[String],
        ports: Vec<PortRange>,
        note: Option<String>,
    ) -> Result<RuleId, SiteError> {
        let resolve = |list: &[String]| -> Result<Vec<Selector>, SiteError> {
            let mut out: Vec<Selector> = Vec::new();
            for text in list {
                let s = self.parse_selector(text)?;
                if !out.contains(&s) {
                    out.push(s);
                }
            }
            Ok(out)
        };
        let rule = Rule {
            from: resolve(from)?,
            to: resolve(to)?,
            ports,
            note,
        };
        if let Some((id, _)) = self.rules.iter().find(|(_, r)| **r == rule) {
            return Err(SiteError::invalid(format!("rule {id} already allows this")));
        }
        let id = RuleId(self.next_rule);
        self.next_rule = self
            .next_rule
            .checked_add(1)
            .ok_or_else(|| SiteError::invalid("rule counter overflow"))?;
        self.rules.insert(id, rule);
        self.check()?;
        Ok(id)
    }

    fn remove_rule_in(&mut self, id: RuleId) -> Result<(), SiteError> {
        self.rules
            .remove(&id)
            .map(|_| ())
            .ok_or_else(|| SiteError::invalid(format!("there is no rule {id}")))
    }

    /// `mac`、`edge-vps.edge`、`mac-app.routes`。
    pub fn parse_selector(&self, text: &str) -> Result<Selector, SiteError> {
        let (name, part) = if let Some(name) = text.strip_suffix(".edge") {
            (name, Part::Edge)
        } else if let Some(name) = text.strip_suffix(".routes") {
            (name, Part::Routes)
        } else {
            (text, Part::Mesh)
        };
        let name: NodeName = name
            .parse()
            .map_err(|e| SiteError::invalid(format!("`{text}`: {e}")))?;
        let m = self.machine(&name)?;
        match part {
            Part::Edge if m.edge.is_none() => Err(SiteError::invalid(format!(
                "`{text}`: `{name}` runs no Edge; `nett site edge {name} <address>` sets one"
            ))),
            Part::Routes if m.routes.is_empty() => Err(SiteError::invalid(format!(
                "`{text}`: `{name}` advertises no routes; `nett site routes {name} <prefix>` sets them"
            ))),
            _ => Ok(Selector {
                node: m.node_id.clone(),
                part,
            }),
        }
    }

    /// 删除规则中匹配的选择器；一边只剩空时整条删除（design/site.md 第 5.1 节）。
    fn strip(&mut self, gone: impl Fn(&Selector) -> bool) {
        for rule in self.rules.values_mut() {
            rule.from.retain(|s| !gone(s));
            rule.to.retain(|s| !gone(s));
        }
        self.rules
            .retain(|_, r| !r.from.is_empty() && !r.to.is_empty());
    }

    /// 分配下一对地址：组网网段中的第 `next_host` 个（不回收，design/mesh.md 第 3 节）。
    fn allocate(&mut self) -> Result<MeshAddresses, SiteError> {
        let (IpAddr::V4(v4), IpAddr::V6(v6)) =
            (self.prefixes.ipv4.addr(), self.prefixes.ipv6.addr())
        else {
            return Err(SiteError::invalid(
                "mesh prefixes must be one IPv4 and one IPv6 prefix",
            ));
        };
        let n = self.next_host;
        let addrs = MeshAddresses {
            ipv4: Ipv4Addr::from(u32::from(v4) + n),
            ipv6: Ipv6Addr::from(u128::from(v6) + u128::from(n)),
        };
        if !self.prefixes.ipv4.contains(addrs.ipv4.into()) || addrs.ipv4.is_broadcast() {
            return Err(SiteError::invalid(format!(
                "the IPv4 mesh prefix {} has no addresses left",
                self.prefixes.ipv4
            )));
        }
        self.next_host = n
            .checked_add(1)
            .ok_or_else(|| SiteError::invalid("address counter overflow"))?;
        Ok(addrs)
    }
}
