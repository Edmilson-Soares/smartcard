//! fogusmartcard — leitura, gravação e reconhecimento de smart cards (PC/SC)
//! com API C para o `fogu:ffi`.
//!
//! Convenções (Fogu 0.7+: o fogu:ffi aceita qualquer número de argumentos e
//! callbacks; ver `cb.rs` e `fsc_set_sink`):
//! - Contextos e cartões conectados são handles `i64` (> 0).
//! - Funções de status retornam `0` em sucesso e `-1` em erro; a mensagem
//!   fica disponível em `fsc_last_error`.
//! - Respostas (JSON ou hex) são escritas num buffer do chamador
//!   (`ffi.alloc`), terminadas em NUL. O retorno é o tamanho escrito,
//!   `-(tamanho necessário)` se o buffer for pequeno demais, ou -1 em erro.
//!   Quando o buffer é pequeno, a saída fica guardada e é buscada com
//!   `fsc_pending` num buffer maior, sem repetir a operação (um APDU de
//!   gravação nunca é reenviado por causa disso).
//! - Bytes entram e saem em hex (`"00A40400"`; espaços são aceitos na entrada).
//! - Comandos que conversam com o cartão rodam numa transação PC/SC.

mod cb;
pub mod apdu;
pub mod atr;
pub mod identify;
pub mod reader;
pub mod storage;

use std::collections::HashMap;
use std::ffi::{CStr, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use apdu::{Apdu, parse_hex, to_hex};
use reader::{CardH, Ctx};

static CTXS: LazyLock<Mutex<HashMap<i64, Arc<Mutex<Ctx>>>>> = LazyLock::new(Default::default);
static CARDS: LazyLock<Mutex<HashMap<i64, Arc<Mutex<CardH>>>>> = LazyLock::new(Default::default);
static NEXT_HANDLE: AtomicI64 = AtomicI64::new(1);
static LAST_ERROR: Mutex<String> = Mutex::new(String::new());
/// Saída que não coube no buffer do chamador (ver `fsc_pending`).
static PENDING: Mutex<Option<String>> = Mutex::new(None);

/// Bits de `flags` em transmit/apdu/batch.
const RAW: i32 = 1; // não seguir 61xx/6Cxx
const STOP_ON_ERROR: i32 = 2; // batch: parar no primeiro SW diferente de 9000
/// Bit de `flags` em write/mifare_write: permite blocos de fabricante/trailer.
const UNSAFE: i32 = 1;

fn set_error(msg: impl Into<String>) {
    *LAST_ERROR.lock().unwrap() = msg.into();
}

/// Executa `f` sem deixar um panic atravessar a fronteira C.
fn guard<T>(on_error: T, f: impl FnOnce() -> Result<T, String>) -> T {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            set_error(e);
            on_error
        }
        Err(_) => {
            set_error("internal panic in fogusmartcard");
            on_error
        }
    }
}

fn new_handle() -> i64 {
    NEXT_HANDLE.fetch_add(1, Ordering::Relaxed)
}

fn with_ctx<T>(handle: i64, f: impl FnOnce(&mut Ctx) -> Result<T, String>) -> Result<T, String> {
    let ctx = CTXS.lock().unwrap().get(&handle).cloned().ok_or_else(|| format!("invalid context handle {handle}"))?;
    let mut ctx = ctx.lock().unwrap_or_else(|e| e.into_inner());
    f(&mut ctx)
}

fn with_card<T>(handle: i64, f: impl FnOnce(&mut CardH) -> Result<T, String>) -> Result<T, String> {
    let card = CARDS.lock().unwrap().get(&handle).cloned().ok_or_else(|| format!("invalid card handle {handle}"))?;
    let mut card = card.lock().unwrap_or_else(|e| e.into_inner());
    f(&mut card)
}

unsafe fn text<'a>(ptr: *const c_char) -> Result<&'a str, String> {
    if ptr.is_null() {
        return Ok("");
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().map_err(|_| "string is not valid UTF-8".to_string())
}

unsafe fn hex_arg(ptr: *const c_char) -> Result<Vec<u8>, String> {
    parse_hex(unsafe { text(ptr) }?)
}

/// Chave MIFARE em hex; vazia = chave de fábrica FFFFFFFFFFFF.
unsafe fn key_arg(ptr: *const c_char) -> Result<Vec<u8>, String> {
    let key = unsafe { hex_arg(ptr) }?;
    Ok(if key.is_empty() { storage::DEFAULT_KEY.to_vec() } else { key })
}

unsafe fn json_arg(ptr: *const c_char) -> Result<Value, String> {
    let s = unsafe { text(ptr) }?;
    if s.trim().is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(s).map_err(|e| format!("invalid JSON argument: {e}"))
}

fn u16_arg(value: i64, what: &str) -> Result<u16, String> {
    u16::try_from(value).map_err(|_| format!("{what} must be 0..=65535"))
}

unsafe fn write_out(buf: *mut u8, cap: i64, s: &str) -> i64 {
    if let Some(n) = cb::try_sink(buf, cap, s.as_bytes()) {
        return n;
    }
    let need = s.len() + 1;
    if buf.is_null() || cap < need as i64 {
        *PENDING.lock().unwrap() = Some(s.to_string());
        return -(need as i64);
    }
    unsafe {
        std::ptr::copy_nonoverlapping(s.as_ptr(), buf, s.len());
        *buf.add(s.len()) = 0;
    }
    s.len() as i64
}

unsafe fn write_json(buf: *mut u8, cap: i64, value: Value) -> i64 {
    unsafe { write_out(buf, cap, &value.to_string()) }
}

/// Versão da biblioteca. Retorna o tamanho escrito (ver convenções).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsc_version(buf: *mut u8, cap: i64) -> i64 {
    unsafe { write_out(buf, cap, env!("CARGO_PKG_VERSION")) }
}

/// Saída da última chamada que não coube no buffer (retornou `-(tamanho)`).
/// Retorna o tamanho escrito, `-(tamanho)` se ainda não couber, ou -1 se
/// não há nada pendente. Só a saída mais recente é guardada.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsc_pending(buf: *mut u8, cap: i64) -> i64 {
    let Some(s) = PENDING.lock().unwrap().take() else {
        set_error("no pending output");
        return -1;
    };
    unsafe { write_out(buf, cap, &s) }
}

/// Última mensagem de erro. Retorna o tamanho escrito (0 se não há erro).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsc_last_error(buf: *mut u8, cap: i64) -> i64 {
    let msg = LAST_ERROR.lock().unwrap().clone();
    unsafe { write_out(buf, cap, &msg) }
}

// ---- contexto e leitores ----------------------------------------------

/// Abre um contexto PC/SC. Retorna o handle (> 0) ou -1.
#[unsafe(no_mangle)]
pub extern "C" fn fsc_open() -> i64 {
    guard(-1, || {
        let ctx = Ctx::establish()?;
        let handle = new_handle();
        CTXS.lock().unwrap().insert(handle, Arc::new(Mutex::new(ctx)));
        Ok(handle)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn fsc_close(ctx: i64) -> i32 {
    guard(-1, || {
        let c = CTXS.lock().unwrap().remove(&ctx).ok_or_else(|| format!("invalid context handle {ctx}"))?;
        drop(c.lock().unwrap_or_else(|e| e.into_inner()));
        Ok(0)
    })
}

/// `[{"name", "card", "atr", "state": [...], "card_name"}]`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsc_readers(ctx: i64, buf: *mut u8, cap: i64) -> i64 {
    guard(-1, || {
        let v = with_ctx(ctx, |c| c.readers())?;
        Ok(unsafe { write_json(buf, cap, v) })
    })
}

/// Espera até `timeout_ms` (< 0 = sem limite) por eventos e escreve
/// `[{"event": "inserted" | "removed" | "reader_added" | "reader_removed",
/// "reader", "atr", "name", "kind"}]`; `[]` se o tempo acabou.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsc_wait(ctx: i64, timeout_ms: i64, buf: *mut u8, cap: i64) -> i64 {
    guard(-1, || {
        let timeout = u64::try_from(timeout_ms).ok().map(Duration::from_millis);
        let events = with_ctx(ctx, |c| c.wait(timeout))?;
        Ok(unsafe { write_json(buf, cap, json!(events)) })
    })
}

// ---- conexão -----------------------------------------------------------

/// Conecta ao cartão de `reader` (vazio = primeiro leitor com cartão).
/// `opts_json`: `{"share": "shared" | "exclusive" | "direct", "protocol":
/// "any" | "t0" | "t1" | "raw"}` (pode ser vazio). Retorna o handle ou -1.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsc_connect(ctx: i64, reader: *const c_char, opts_json: *const c_char) -> i64 {
    guard(-1, || {
        let name = unsafe { text(reader) }?;
        let opts = unsafe { json_arg(opts_json) }?;
        let card = with_ctx(ctx, |c| c.connect(name, &opts))?;
        let handle = new_handle();
        CARDS.lock().unwrap().insert(handle, Arc::new(Mutex::new(card)));
        Ok(handle)
    })
}

/// `disposition`: 0 deixa o cartão, 1 reset, 2 desliga, 3 ejeta.
#[unsafe(no_mangle)]
pub extern "C" fn fsc_disconnect(card: i64, disposition: i32) -> i32 {
    guard(-1, || {
        let d = reader::disposition(disposition)?;
        let c = CARDS.lock().unwrap().remove(&card).ok_or_else(|| format!("invalid card handle {card}"))?;
        // Se uma chamada ainda segura o cartão, ele é solto quando ela terminar.
        if let Ok(m) = Arc::try_unwrap(c) { m.into_inner().unwrap_or_else(|e| e.into_inner()).disconnect(d)? }
        Ok(0)
    })
}

/// Reconecta (ex. depois de um reset por outro programa). `init`: 0 sem
/// reset, 1 reset a quente, 2 desliga e religa.
#[unsafe(no_mangle)]
pub extern "C" fn fsc_reconnect(card: i64, init: i32) -> i32 {
    guard(-1, || {
        let d = reader::disposition(init)?;
        with_card(card, |c| c.reconnect(d))?;
        Ok(0)
    })
}

/// `{"reader", "atr", "protocol", "kind", "family"}`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsc_card_status(card: i64, buf: *mut u8, cap: i64) -> i64 {
    guard(-1, || {
        let v = with_card(card, |c| c.status())?;
        Ok(unsafe { write_json(buf, cap, v) })
    })
}

/// Atributos do leitor (fabricante, modelo, serial...), os que o driver informar.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsc_attributes(card: i64, buf: *mut u8, cap: i64) -> i64 {
    guard(-1, || {
        let v = with_card(card, |c| Ok(c.attributes()))?;
        Ok(unsafe { write_json(buf, cap, v) })
    })
}

// ---- APDUs -------------------------------------------------------------

/// Envia um APDU em hex. Escreve `{"data", "sw", "sw1", "sw2", "ok",
/// "status"}`. `flags`: 1 = modo bruto (não seguir 61xx/6Cxx).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsc_transmit(card: i64, apdu_hex: *const c_char, flags: i32, buf: *mut u8, cap: i64) -> i64 {
    guard(-1, || {
        let cmd = unsafe { hex_arg(apdu_hex) }?;
        let r = with_card(card, |c| c.run(|t| apdu::transmit(t, &cmd, flags & RAW == 0)))?;
        Ok(unsafe { write_json(buf, cap, r.to_json()) })
    })
}

/// Monta e envia um APDU descrito em JSON: `{"cla", "ins", "p1", "p2",
/// "data": "hex", "le"}` (curto ou estendido conforme os tamanhos).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsc_apdu(card: i64, apdu_json: *const c_char, flags: i32, buf: *mut u8, cap: i64) -> i64 {
    guard(-1, || {
        let cmd = Apdu::from_json(&unsafe { json_arg(apdu_json) }?)?.encode()?;
        let r = with_card(card, |c| c.run(|t| apdu::transmit(t, &cmd, flags & RAW == 0)))?;
        Ok(unsafe { write_json(buf, cap, r.to_json()) })
    })
}

/// Envia vários APDUs (lista JSON de hex ou de objetos como em `fsc_apdu`)
/// numa única transação. `flags`: 1 = bruto, 2 = parar no primeiro SW != 9000.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsc_transmit_batch(card: i64, list_json: *const c_char, flags: i32, buf: *mut u8, cap: i64) -> i64 {
    guard(-1, || {
        let list = unsafe { json_arg(list_json) }?;
        let items = list.as_array().ok_or("batch must be a JSON list")?;
        let cmds = items
            .iter()
            .map(|it| match it {
                Value::String(s) => parse_hex(s),
                Value::Object(_) => Apdu::from_json(it)?.encode(),
                _ => Err("batch items must be hex strings or APDU objects".into()),
            })
            .collect::<Result<Vec<_>, String>>()?;
        let out = with_card(card, |c| {
            c.run(|t| {
                let mut out = Vec::new();
                for cmd in &cmds {
                    let r = apdu::transmit(t, cmd, flags & RAW == 0)?;
                    let stop = flags & STOP_ON_ERROR != 0 && !r.ok();
                    out.push(r.to_json());
                    if stop {
                        break;
                    }
                }
                Ok(out)
            })
        })?;
        Ok(unsafe { write_json(buf, cap, json!(out)) })
    })
}

/// SCardControl com o número de função do driver (ex. 3500 para o escape
/// dos leitores ACS). Escreve a resposta em hex.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsc_control(card: i64, code: i64, data_hex: *const c_char, buf: *mut u8, cap: i64) -> i64 {
    guard(-1, || {
        let data = unsafe { hex_arg(data_hex) }?;
        let code = u32::try_from(code).map_err(|_| "control code must be 0..=4294967295".to_string())?;
        let out = with_card(card, |c| c.control(code, &data))?;
        Ok(unsafe { write_out(buf, cap, &to_hex(&out)) })
    })
}

// ---- reconhecimento ----------------------------------------------------

/// Decodifica um ATR (hex): protocolos, Fi/Di, T=1, bytes históricos...
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsc_parse_atr(atr_hex: *const c_char, buf: *mut u8, cap: i64) -> i64 {
    guard(-1, || {
        let atr = atr::Atr::parse(&unsafe { hex_arg(atr_hex) }?)?;
        Ok(unsafe { write_json(buf, cap, atr.to_json()) })
    })
}

/// Identifica o modelo pelo ATR (hex), sem precisar de leitor:
/// `{"name", "kind", "family", "interface", "confidence", "source", "matches", ...}`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsc_identify_atr(atr_hex: *const c_char, buf: *mut u8, cap: i64) -> i64 {
    guard(-1, || {
        let atr = unsafe { hex_arg(atr_hex) }?;
        Ok(unsafe { write_json(buf, cap, identify::identify_atr(&atr)) })
    })
}

/// Identifica o cartão conectado. `flags`: 1 = sondar também (UID e SELECT
/// das aplicações conhecidas: EMV, PIV, OpenPGP, FIDO, PKCS#15, NDEF, GP).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsc_identify(card: i64, flags: i32, buf: *mut u8, cap: i64) -> i64 {
    guard(-1, || {
        let v = with_card(card, |c| {
            let mut id = identify::identify_atr(&c.atr);
            if flags & 1 != 0 {
                c.run(|t| {
                    identify::probe(t, &mut id);
                    Ok(())
                })?;
            }
            id.as_object_mut().unwrap().insert("reader".into(), json!(c.reader));
            Ok(id)
        })?;
        Ok(unsafe { write_json(buf, cap, v) })
    })
}

/// Carrega uma base de ATRs: `.json` (`[{"atr", "name", "kind"}]`) ou o
/// formato do `smartcard_list.txt`. Retorna quantas entradas entraram ou -1.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsc_db_load(path: *const c_char) -> i64 {
    guard(-1, || Ok(identify::load_file(unsafe { text(path) }?)? as i64))
}

#[unsafe(no_mangle)]
pub extern "C" fn fsc_db_clear() -> i32 {
    identify::clear();
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn fsc_db_count() -> i64 {
    identify::count() as i64
}

// ---- cartões de memória (PC/SC parte 3) --------------------------------

/// UID do cartão sem contato, em hex.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsc_uid(card: i64, buf: *mut u8, cap: i64) -> i64 {
    guard(-1, || {
        let uid = with_card(card, |c| c.run(storage::uid))?;
        Ok(unsafe { write_out(buf, cap, &to_hex(&uid)) })
    })
}

/// Carrega a chave (hex de 6 bytes, vazio = FFFFFFFFFFFF) e autentica o
/// setor do bloco. `key_type`: 0 = A, 1 = B.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsc_mifare_auth(card: i64, block: i64, key_hex: *const c_char, key_type: i32) -> i32 {
    guard(-1, || {
        let block = u16_arg(block, "block")?;
        let key = unsafe { key_arg(key_hex) }?;
        with_card(card, |c| c.run(|t| storage::login(t, block, &key, key_type)))?;
        Ok(0)
    })
}

/// READ BINARY (`FF B0`): `len` bytes do bloco/página `addr`, em hex. Em
/// MIFARE Classic o setor precisa estar autenticado (`fsc_mifare_auth`);
/// em Ultralight cada leitura traz 4 páginas (16 bytes).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsc_read(card: i64, addr: i64, len: i64, buf: *mut u8, cap: i64) -> i64 {
    guard(-1, || {
        let addr = u16_arg(addr, "address")?;
        let len = u16_arg(len, "length")?;
        let data = with_card(card, |c| c.run(|t| storage::read_binary(t, addr, len)))?;
        Ok(unsafe { write_out(buf, cap, &to_hex(&data)) })
    })
}

/// UPDATE BINARY (`FF D6`) com as regras do tipo do cartão: MIFARE Classic
/// grava 16 bytes e protege bloco 0 e trailers; Ultralight grava de 4 em 4
/// bytes e protege as páginas 0..3. `flags`: 1 = permitir essas áreas.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsc_write(card: i64, addr: i64, data_hex: *const c_char, flags: i32) -> i32 {
    guard(-1, || {
        let addr = u16_arg(addr, "address")?;
        let data = unsafe { hex_arg(data_hex) }?;
        let allow = flags & UNSAFE != 0;
        with_card(card, |c| match c.family() {
            "mifare_classic" => {
                storage::check_classic_write(addr, &data, allow)?;
                c.run(|t| storage::update_binary(t, addr, &data))
            }
            "mifare_ultralight" => c.run(|t| storage::ultralight_write(t, addr, &data, allow)),
            _ => c.run(|t| storage::update_binary(t, addr, &data)),
        })?;
        Ok(0)
    })
}

/// Autentica e lê um bloco MIFARE Classic (16 bytes, em hex).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsc_mifare_read(card: i64, block: i64, key_hex: *const c_char, key_type: i32, buf: *mut u8, cap: i64) -> i64 {
    guard(-1, || {
        let block = u16_arg(block, "block")?;
        let key = unsafe { key_arg(key_hex) }?;
        let data = with_card(card, |c| c.run(|t| storage::classic_read(t, block, &key, key_type)))?;
        Ok(unsafe { write_out(buf, cap, &to_hex(&data)) })
    })
}

/// Autentica e lê um setor inteiro: lista JSON de blocos em hex.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsc_mifare_read_sector(card: i64, sector: i64, key_hex: *const c_char, key_type: i32, buf: *mut u8, cap: i64) -> i64 {
    guard(-1, || {
        let sector = u16_arg(sector, "sector")?;
        let key = unsafe { key_arg(key_hex) }?;
        let blocks = with_card(card, |c| c.run(|t| storage::classic_read_sector(t, sector, &key, key_type)))?;
        let list: Vec<String> = blocks.iter().map(|b| to_hex(b)).collect();
        Ok(unsafe { write_json(buf, cap, json!(list)) })
    })
}

/// Autentica e grava um bloco MIFARE Classic (16 bytes em hex). `flags`:
/// 1 = permitir bloco 0 e trailers (bits de acesso são sempre conferidos).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsc_mifare_write(card: i64, block: i64, data_hex: *const c_char, key_hex: *const c_char, key_type: i32, flags: i32) -> i32 {
    guard(-1, || {
        let block = u16_arg(block, "block")?;
        let data = unsafe { hex_arg(data_hex) }?;
        let key = unsafe { key_arg(key_hex) }?;
        with_card(card, |c| c.run(|t| storage::classic_write(t, block, &data, &key, key_type, flags & UNSAFE != 0)))?;
        Ok(0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn call(f: impl FnOnce(*mut u8, i64) -> i64) -> (i64, String) {
        let mut buf = vec![0u8; 8192];
        let n = f(buf.as_mut_ptr(), buf.len() as i64);
        let s = if n >= 0 { String::from_utf8(buf[..n as usize].to_vec()).unwrap() } else { String::new() };
        (n, s)
    }

    #[test]
    fn version_and_small_buffer() {
        let (n, v) = call(|b, c| unsafe { fsc_version(b, c) });
        assert_eq!(v, env!("CARGO_PKG_VERSION"));
        assert_eq!(n as usize, v.len());
    }

    #[test]
    fn atr_functions_over_ffi() {
        let atr = CString::new("3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 01 00 00 00 00 6A").unwrap();
        let (_, j) = call(|b, c| unsafe { fsc_identify_atr(atr.as_ptr(), b, c) });
        let v: Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["name"], "MIFARE Classic 1K");
        let (_, j) = call(|b, c| unsafe { fsc_parse_atr(atr.as_ptr(), b, c) });
        let v: Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["tck_ok"], true);
        let bad = CString::new("3B 8F").unwrap();
        assert_eq!(call(|b, c| unsafe { fsc_parse_atr(bad.as_ptr(), b, c) }).0, -1);
        let (_, e) = call(|b, c| unsafe { fsc_last_error(b, c) });
        assert!(e.contains("truncated"));
    }

    #[test]
    fn pending_output_is_kept() {
        let atr = CString::new("3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 01 00 00 00 00 6A").unwrap();
        let mut tiny = [0u8; 4];
        let n = unsafe { fsc_parse_atr(atr.as_ptr(), tiny.as_mut_ptr(), 4) };
        assert!(n < -1);
        let (m, j) = call(|b, c| unsafe { fsc_pending(b, c) });
        assert_eq!(m, -n - 1);
        assert!(j.contains("MIFARE") || j.contains("tck_ok"));
        assert_eq!(call(|b, c| unsafe { fsc_pending(b, c) }).0, -1);

        // Tudo que usa PENDING (global) fica neste teste, em sequência.
        let v = env!("CARGO_PKG_VERSION");
        let mut tiny = [0u8; 2];
        assert_eq!(unsafe { fsc_version(tiny.as_mut_ptr(), 2) }, -(v.len() as i64 + 1));
        assert_eq!(call(|b, c| unsafe { fsc_pending(b, c) }).1, v);
    }

    #[test]
    fn invalid_handles() {
        assert_eq!(fsc_close(999_999), -1);
        assert_eq!(fsc_disconnect(999_999, 0), -1);
        let apdu = CString::new("00A40400").unwrap();
        assert_eq!(call(|b, c| unsafe { fsc_transmit(999_999, apdu.as_ptr(), 0, b, c) }).0, -1);
    }
}

/// Registra (ou remove, com NULL) o callback (Fogu 0.7+, `ffi.callback`) que
/// recebe as saídas das funções chamadas com `buf = NULL, cap = 0`: a resposta
/// chega inteira de uma vez, sem buffer fixo nem `fsc_pending` (ver `cb.rs`).
#[unsafe(no_mangle)]
pub extern "C" fn fsc_set_sink(sink: Option<cb::Sink>) -> i32 {
    cb::set_sink(sink);
    0
}
