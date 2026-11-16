//! PC/SC: contexto, leitores, eventos e conexões com cartões. Usa WinSCard
//! no Windows, pcsc-lite no Linux e PCSC.framework no macOS.

use std::collections::HashMap;
use std::ffi::CString;
use std::time::{Duration, Instant};

use pcsc::{Context, Disposition, Error, PNP_NOTIFICATION, Protocol, Protocols, ReaderState, Scope, ShareMode, State};
use serde_json::{Value, json};

use crate::apdu::{Transport, spaced, to_hex};
use crate::identify;

pub fn err(e: Error) -> String {
    format!("{e} ({e:?})")
}

/// Erros que pedem um novo contexto: o serviço de smart card do Windows
/// para quando o último leitor é removido e invalida os contextos abertos.
fn service_gone(e: Error) -> bool {
    matches!(e, Error::ServiceStopped | Error::NoService | Error::InvalidHandle)
}

fn state_names(s: State) -> Vec<&'static str> {
    [
        (State::IGNORE, "ignore"),
        (State::UNKNOWN, "unknown"),
        (State::UNAVAILABLE, "unavailable"),
        (State::EMPTY, "empty"),
        (State::PRESENT, "present"),
        (State::ATRMATCH, "atr_match"),
        (State::EXCLUSIVE, "exclusive"),
        (State::INUSE, "inuse"),
        (State::MUTE, "mute"),
        (State::UNPOWERED, "unpowered"),
    ]
    .iter()
    .filter(|(flag, _)| s.contains(*flag))
    .map(|(_, n)| *n)
    .collect()
}

fn present(s: State) -> bool {
    s.contains(State::PRESENT) && !s.contains(State::UNAVAILABLE)
}

struct Known {
    state: State,
    atr: Vec<u8>,
}

pub struct Ctx {
    /// None enquanto o serviço PC/SC não está rodando (no Windows ele só
    /// sobe quando há um leitor conectado); cada uso tenta abrir de novo.
    ctx: Option<Context>,
    known: HashMap<String, Known>,
    pnp: State,
}

fn open_context() -> Result<Option<Context>, String> {
    match Context::establish(Scope::User) {
        Ok(c) => Ok(Some(c)),
        Err(e) if service_gone(e) => Ok(None),
        Err(e) => Err(format!("cannot open PC/SC context: {}", err(e))),
    }
}

impl Ctx {
    pub fn establish() -> Result<Ctx, String> {
        Ok(Ctx { ctx: open_context()?, known: HashMap::new(), pnp: State::UNAWARE })
    }

    fn reestablish(&mut self) {
        self.ctx = open_context().ok().flatten();
        self.pnp = State::UNAWARE;
    }

    /// O contexto, abrindo-o se o serviço subiu desde a última tentativa.
    fn context(&mut self) -> Option<&Context> {
        if self.ctx.is_none() {
            self.reestablish();
        }
        self.ctx.as_ref()
    }

    pub fn reader_names(&mut self) -> Result<Vec<String>, String> {
        for _ in 0..2 {
            let Some(ctx) = self.context() else { return Ok(Vec::new()) };
            match ctx.list_readers_owned() {
                Ok(v) => return Ok(v.into_iter().map(|c| c.to_string_lossy().into_owned()).collect()),
                Err(Error::NoReadersAvailable) => return Ok(Vec::new()),
                Err(e) if service_gone(e) => self.reestablish(),
                Err(e) => return Err(format!("cannot list readers: {}", err(e))),
            }
        }
        Ok(Vec::new())
    }

    /// Estado atual de cada leitor: `[{name, card, atr, state, card_name}]`.
    pub fn readers(&mut self) -> Result<Value, String> {
        let names = self.reader_names()?;
        let Some(ctx) = self.ctx.as_ref().filter(|_| !names.is_empty()) else { return Ok(json!([])) };
        let mut states = to_states(&names, |_| State::UNAWARE)?;
        match ctx.get_status_change(Duration::ZERO, &mut states) {
            Ok(()) | Err(Error::Timeout) => {}
            Err(e) => return Err(format!("cannot read reader status: {}", err(e))),
        }
        Ok(states.iter().map(|rs| reader_json(rs.name().to_string_lossy().as_ref(), rs.event_state(), rs.atr())).collect())
    }

    /// Espera mudanças (cartão inserido/removido, leitor conectado/removido)
    /// por até `timeout` (None = para sempre). Devolve a lista de eventos,
    /// vazia se o tempo acabar. Na primeira chamada, cartões já inseridos
    /// aparecem como `inserted`.
    pub fn wait(&mut self, timeout: Option<Duration>) -> Result<Vec<Value>, String> {
        let deadline = timeout.map(|t| Instant::now() + t);
        let expired = || deadline.is_some_and(|d| Instant::now() >= d);
        loop {
            let names = self.reader_names()?;
            let mut events = Vec::new();
            let gone: Vec<String> = self.known.keys().filter(|k| !names.contains(k)).cloned().collect();
            for name in gone {
                let k = self.known.remove(&name).unwrap();
                if present(k.state) {
                    events.push(json!({ "event": "removed", "reader": name, "atr": spaced(&k.atr) }));
                }
                events.push(json!({ "event": "reader_removed", "reader": name }));
            }
            if !events.is_empty() {
                return Ok(events);
            }

            let Some(ctx) = self.ctx.as_ref() else {
                // Serviço parado (Windows sem leitor): consulta de novo em
                // instantes, até um leitor aparecer ou o tempo acabar.
                if expired() {
                    return Ok(Vec::new());
                }
                nap(deadline, 250);
                continue;
            };
            let mut states = to_states(&names, |n| self.known.get(n).map(|k| k.state).unwrap_or(State::UNAWARE))?;
            // Leitor virtual que avisa quando leitores são conectados/removidos.
            states.push(ReaderState::new(PNP_NOTIFICATION(), self.pnp));
            let remaining = deadline.map(|d| d.saturating_duration_since(Instant::now()));
            match ctx.get_status_change(remaining, &mut states) {
                Ok(()) => {}
                Err(Error::Timeout) => return Ok(Vec::new()),
                Err(e) if service_gone(e) || e == Error::NoReadersAvailable || e == Error::UnknownReader => {
                    self.reestablish();
                    if expired() {
                        return Ok(Vec::new());
                    }
                    nap(deadline, 250);
                    continue;
                }
                Err(e) => return Err(format!("cannot wait for card events: {}", err(e))),
            }

            for rs in &states {
                let mut state = rs.event_state();
                state.remove(State::CHANGED);
                if rs.name() == PNP_NOTIFICATION() {
                    self.pnp = state;
                    continue;
                }
                let name = rs.name().to_string_lossy().into_owned();
                let atr = rs.atr().to_vec();
                let now = present(state);
                match self.known.get(&name) {
                    None => {
                        events.push(json!({ "event": "reader_added", "reader": name }));
                        if now {
                            events.push(inserted(&name, &atr));
                        }
                    }
                    Some(prev) => {
                        let was = present(prev.state);
                        if was && (!now || prev.atr != atr) {
                            events.push(json!({ "event": "removed", "reader": name, "atr": spaced(&prev.atr) }));
                        }
                        if now && (!was || prev.atr != atr) {
                            events.push(inserted(&name, &atr));
                        }
                    }
                }
                self.known.insert(name, Known { state, atr });
            }
            if !events.is_empty() {
                return Ok(events);
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                return Ok(Vec::new());
            }
        }
    }

    /// Conecta ao cartão do leitor `reader` (vazio = primeiro leitor com
    /// cartão). Opções: `share` (shared | exclusive | direct) e `protocol`
    /// (any | t0 | t1 | raw).
    pub fn connect(&mut self, reader: &str, opts: &Value) -> Result<CardH, String> {
        let share = match opts.get("share").and_then(Value::as_str).unwrap_or("shared") {
            "shared" => ShareMode::Shared,
            "exclusive" => ShareMode::Exclusive,
            "direct" => ShareMode::Direct,
            other => return Err(format!("invalid share mode '{other}' (shared, exclusive, direct)")),
        };
        let protocols = match opts.get("protocol").and_then(Value::as_str).unwrap_or("any") {
            _ if share == ShareMode::Direct => Protocols::UNDEFINED,
            "any" => Protocols::ANY,
            "t0" | "T0" => Protocols::T0,
            "t1" | "T1" => Protocols::T1,
            "raw" => Protocols::RAW,
            other => return Err(format!("invalid protocol '{other}' (any, t0, t1, raw)")),
        };
        let name = if reader.is_empty() { self.first_with_card()? } else { reader.to_string() };
        let cname = CString::new(name.clone()).map_err(|_| "reader name contains NUL".to_string())?;
        let no_service = || "no smart card reader found (PC/SC service not running)".to_string();
        let mut result = self.context().ok_or_else(no_service)?.connect(&cname, share, protocols);
        if matches!(result, Err(e) if service_gone(e)) {
            self.reestablish();
            result = self.context().ok_or_else(no_service)?.connect(&cname, share, protocols);
        }
        let card = result.map_err(|e| match e {
            Error::NoSmartcard | Error::RemovedCard => format!("no card in reader '{name}'"),
            Error::UnknownReader => format!("unknown reader '{name}'"),
            Error::SharingViolation => format!("card in '{name}' is in exclusive use by another program"),
            e => format!("cannot connect to '{name}': {}", err(e)),
        })?;
        let mut h = CardH { card, reader: name, share, protocols, kind: String::new(), atr: Vec::new() };
        h.refresh();
        Ok(h)
    }

    fn first_with_card(&mut self) -> Result<String, String> {
        let readers = self.readers()?;
        let list = readers.as_array().unwrap();
        if list.is_empty() {
            return Err("no smart card reader found".into());
        }
        list.iter()
            .find(|r| r["card"] == true)
            .and_then(|r| r["name"].as_str().map(str::to_string))
            .ok_or_else(|| "no card in any reader".to_string())
    }
}

fn to_states(names: &[String], current: impl Fn(&str) -> State) -> Result<Vec<ReaderState>, String> {
    names
        .iter()
        .map(|n| Ok(ReaderState::new(CString::new(n.as_str()).map_err(|_| "reader name contains NUL")?, current(n))))
        .collect()
}

fn reader_json(name: &str, state: State, atr: &[u8]) -> Value {
    let card = present(state);
    let mut v = json!({
        "name": name,
        "card": card,
        "atr": if card { json!(spaced(atr)) } else { Value::Null },
        "state": state_names(state),
    });
    if card && !atr.is_empty() {
        v["card_name"] = identify::identify_atr(atr)["name"].clone();
    }
    v
}

fn inserted(reader: &str, atr: &[u8]) -> Value {
    let id = identify::identify_atr(atr);
    json!({ "event": "inserted", "reader": reader, "atr": spaced(atr), "name": id["name"], "kind": id["kind"] })
}

pub struct CardH {
    pub card: pcsc::Card,
    pub reader: String,
    share: ShareMode,
    protocols: Protocols,
    /// Tipo identificado pelo ATR na conexão (ver `identify::family`).
    pub kind: String,
    pub atr: Vec<u8>,
}

impl CardH {
    fn refresh(&mut self) {
        if let Ok(s) = self.card.status2_owned() {
            self.atr = s.atr().to_vec();
        }
        self.kind = identify::identify_atr(&self.atr)["kind"].as_str().unwrap_or("unknown").to_string();
    }

    pub fn family(&self) -> &'static str {
        identify::family(&self.kind)
    }

    pub fn reconnect(&mut self, init: Disposition) -> Result<(), String> {
        self.card.reconnect(self.share, self.protocols, init).map_err(|e| format!("reconnect failed: {}", err(e)))?;
        self.refresh();
        Ok(())
    }

    pub fn status(&self) -> Result<Value, String> {
        let s = self.card.status2_owned().map_err(|e| format!("card status failed: {}", err(e)))?;
        let protocol = match s.protocol2() {
            Some(Protocol::T0) => json!("T0"),
            Some(Protocol::T1) => json!("T1"),
            Some(Protocol::RAW) => json!("RAW"),
            None => Value::Null,
        };
        Ok(json!({
            "reader": self.reader,
            "atr": spaced(s.atr()),
            "protocol": protocol,
            "kind": self.kind,
            "family": self.family(),
        }))
    }

    /// Executa `f` dentro de uma transação PC/SC (nenhum outro programa
    /// intercala comandos). Se o cartão foi resetado por outro programa,
    /// reconecta e tenta de novo uma vez.
    pub fn run<T>(&mut self, mut f: impl FnMut(&mut dyn Transport) -> Result<T, String>) -> Result<T, String> {
        for attempt in 0..2 {
            let started = match self.card.transaction() {
                Ok(tx) => {
                    let mut t = PcscTransport { card: &tx, reset: false };
                    let r = f(&mut t);
                    let reset = t.reset;
                    let _ = tx.end(Disposition::LeaveCard);
                    Ok((r, reset))
                }
                Err(e) => Err(e),
            };
            let (result, reset) = match started {
                Ok(done) => done,
                Err(Error::ResetCard) => (Err("card was reset".to_string()), true),
                // Modo direct e alguns drivers não aceitam transações.
                Err(Error::UnsupportedFeature | Error::InvalidValue) => {
                    let mut t = PcscTransport { card: &self.card, reset: false };
                    let r = f(&mut t);
                    (r, t.reset)
                }
                Err(e) => return Err(format!("cannot start transaction: {}", err(e))),
            };
            if reset && attempt == 0 {
                self.reconnect(Disposition::LeaveCard)?;
                continue;
            }
            return result;
        }
        unreachable!()
    }

    /// SCardControl. `code` é o número da função do driver (ex. 3500, o
    /// escape dos leitores ACS); `ctl_code` aplica a codificação da plataforma.
    pub fn control(&self, code: u32, data: &[u8]) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; pcsc::MAX_BUFFER_SIZE_EXTENDED];
        self.card.control(pcsc::ctl_code(code as _), data, &mut buf).map(|r| r.to_vec()).map_err(|e| format!("control failed: {}", err(e)))
    }

    pub fn attributes(&self) -> Value {
        use pcsc::Attribute as A;
        let mut out = serde_json::Map::new();
        for (key, attr) in [
            ("vendor_name", A::VendorName),
            ("vendor_ifd_type", A::VendorIfdType),
            ("vendor_ifd_version", A::VendorIfdVersion),
            ("vendor_ifd_serial", A::VendorIfdSerialNo),
            ("channel_id", A::ChannelId),
            ("max_ifsd", A::MaxIfsd),
        ] {
            if let Ok(v) = self.card.get_attribute_owned(attr) {
                let text = String::from_utf8_lossy(&v).trim_end_matches('\0').to_string();
                let printable = !text.is_empty() && text.chars().all(|c| !c.is_control());
                out.insert(key.into(), if printable { json!(text) } else { json!(to_hex(&v)) });
            }
        }
        Value::Object(out)
    }

    pub fn disconnect(self, d: Disposition) -> Result<(), String> {
        self.card.disconnect(d).map_err(|(_, e)| format!("disconnect failed: {}", err(e)))
    }
}

struct PcscTransport<'a> {
    card: &'a pcsc::Card,
    reset: bool,
}

impl Transport for PcscTransport<'_> {
    fn exchange(&mut self, apdu: &[u8]) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; pcsc::MAX_BUFFER_SIZE_EXTENDED];
        match self.card.transmit(apdu, &mut buf) {
            Ok(r) => Ok(r.to_vec()),
            Err(e) => {
                if e == Error::ResetCard {
                    self.reset = true;
                }
                Err(match e {
                    Error::RemovedCard => "card was removed".to_string(),
                    e => format!("transmit failed: {}", err(e)),
                })
            }
        }
    }
}

pub fn disposition(code: i32) -> Result<Disposition, String> {
    Ok(match code {
        0 => Disposition::LeaveCard,
        1 => Disposition::ResetCard,
        2 => Disposition::UnpowerCard,
        3 => Disposition::EjectCard,
        _ => return Err(format!("invalid disposition {code} (0 leave, 1 reset, 2 unpower, 3 eject)")),
    })
}

/// Dorme até `ms` milissegundos, sem passar do prazo (esperas curtas, em
/// fatias, não podem virar 250 ms).
fn nap(deadline: Option<Instant>, ms: u64) {
    let mut d = Duration::from_millis(ms);
    if let Some(deadline) = deadline {
        d = d.min(deadline.saturating_duration_since(Instant::now()));
    }
    if !d.is_zero() {
        std::thread::sleep(d);
    }
}
