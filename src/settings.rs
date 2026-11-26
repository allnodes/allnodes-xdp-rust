use std::net::SocketAddrV4;

use crate::error::XdpConfigError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XdpMode {
    Drv,
    Skb,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XdpSettings {
    pub interface: Option<String>,
    pub mode: XdpMode,
    pub zero_copy: bool,
    pub native_bond: bool,
}

/// `listen` ip UNSPECIFIED = all interface addresses; port 0 = reserve one.
#[derive(Clone, Debug)]
pub struct EndpointSpec {
    pub name: &'static str,
    pub listen: SocketAddrV4,
}

fn parse_bool(var: &str, value: &str) -> Result<bool, XdpConfigError> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(XdpConfigError::Invalid {
            var: var.to_string(),
            value: value.to_string(),
            expected: "true/1/yes/on or false/0/no/off",
        }),
    }
}

impl XdpSettings {
    pub fn from_vars(
        prefix: &str,
        get: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>, XdpConfigError> {
        let get = |suffix: &str| -> (String, Option<String>) {
            let var = format!("{prefix}{suffix}");
            let value = get(&var).filter(|v| !v.is_empty());
            (var, value)
        };
        let (switch_var, switch) = get("NET_XDP");
        let on = match &switch {
            Some(v) => parse_bool(&switch_var, v)?,
            None => false,
        };
        let (interface_var, interface) = get("NET_XDP_INTERFACE");
        let (mode_var, mode) = get("NET_XDP_MODE");
        let (zc_var, zc) = get("NET_XDP_ZERO_COPY");
        let (nb_var, nb) = get("NET_XDP_NATIVE_BOND");

        if !on {
            let set = [
                (interface_var, interface.is_some()),
                (mode_var, mode.is_some()),
                (zc_var, zc.is_some()),
                (nb_var, nb.is_some()),
            ];
            if let Some((var, _)) = set.into_iter().find(|(_, is_set)| *is_set) {
                return Err(XdpConfigError::RequiresXdp { var });
            }
            return Ok(None);
        }

        let mode_norm = mode.as_deref().map(|m| m.trim().to_ascii_lowercase());
        let mode = match mode_norm.as_deref() {
            None | Some("drv") => XdpMode::Drv,
            Some("skb") => XdpMode::Skb,
            Some(_) => {
                return Err(XdpConfigError::Invalid {
                    var: mode_var,
                    value: mode.unwrap_or_default(),
                    expected: "drv or skb",
                });
            }
        };
        let zero_copy = match &zc {
            Some(v) => parse_bool(&zc_var, v)?,
            None => false,
        };
        let native_bond = match &nb {
            Some(v) => parse_bool(&nb_var, v)?,
            None => false,
        };
        if zero_copy && mode == XdpMode::Skb {
            return Err(XdpConfigError::ZeroCopyNeedsDrv {
                zero_copy_var: zc_var,
                mode_var,
            });
        }
        Ok(Some(Self {
            interface,
            mode,
            zero_copy,
            native_bond,
        }))
    }

    pub fn from_env(prefix: &str) -> Result<Option<Self>, XdpConfigError> {
        Self::from_vars(prefix, |k| std::env::var(k).ok())
    }
}
