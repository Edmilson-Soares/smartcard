//! Reconhecimento do modelo do cartão: pelo ATR (bases carregadas, padrão
//! PC/SC parte 3, tabela embutida e heurísticas) e, com o cartão conectado,
//! sondando aplicações conhecidas.

use std::sync::{LazyLock, RwLock};

use regex::Regex;
use serde_json::{Map, Value, json};

use crate::apdu::{self, Apdu, Transport, find_all, parse_hex, parse_tlv, spaced, to_hex};
use crate::atr::{Atr, card_name, standard_name};

/// Uma linha de base de ATRs: o padrão é uma regex sobre o ATR em hex
/// maiúsculo separado por espaço (`3B 8F 80 01 ..`), como no
/// `smartcard_list.txt` do pcsc-tools.
pub struct Entry {
    re: Regex,
    pub pattern: String,
    pub names: Vec<String>,
    pub kind: Option<String>,
    pub source: &'static str,
}

impl Entry {
    fn new(pattern: &str, names: Vec<String>, kind: Option<String>, source: &'static str) -> Option<Entry> {
        let pattern = pattern.split_whitespace().collect::<Vec<_>>().join(" ").to_uppercase();
        let re = Regex::new(&format!("^(?:{pattern})$")).ok()?;
        Some(Entry { re, pattern, names, kind, source })
    }

    fn matches(&self, atr: &str) -> bool {
        self.re.is_match(atr)
    }
}

static DB: LazyLock<RwLock<Vec<Entry>>> = LazyLock::new(Default::default);

/// ATRs conhecidos que o padrão PC/SC não descreve: `(padrão, nome, tipo)`.
const BUILTIN: &[(&str, &str, &str)] = &[
    ("3B 81 80 01 80 80", "MIFARE DESFire (EV1/EV2/EV3)", "desfire"),
];

/// Palavras nos bytes históricos que identificam o fabricante/produto.
const KEYWORDS: &[(&str, &str, &str)] = &[
    ("YUBIKEY", "Yubico YubiKey", "token"),
    ("JCOP", "NXP JCOP (Java Card)", "javacard"),
    ("ETOKEN", "SafeNet eToken", "token"),
    ("NITROKEY", "Nitrokey", "token"),
    ("OPENPGP", "Cartão OpenPGP", "openpgp"),
];

/// Aplicações sondadas por SELECT (por nome): `(AID, nome, tipo)`.
const AIDS: &[(&str, &str, &str)] = &[
    ("325041592E5359532E4444463031", "EMV PPSE (2PAY.SYS.DDF01)", "emv"),
    ("315041592E5359532E4444463031", "EMV PSE (1PAY.SYS.DDF01)", "emv"),
    ("A000000308000010000100", "PIV", "piv"),
    ("D27600012401", "OpenPGP", "openpgp"),
    ("A0000006472F0001", "FIDO U2F", "fido"),
    ("A000000063504B43532D3135", "PKCS#15", "pkcs15"),
    ("D2760000850101", "NFC Forum Type 4 (NDEF)", "ndef"),
    ("A000000151000000", "GlobalPlatform ISD", "globalplatform"),
    ("A000000003000000", "GlobalPlatform ISD (Visa OP)", "globalplatform"),
];

/// Nome e tipo do cartão a partir da aplicação encontrada, em ordem de prioridade.
const APP_NAMES: &[(&str, &str)] = &[
    ("emv", "Cartão de pagamento EMV"),
    ("piv", "Cartão PIV"),
    ("openpgp", "Cartão OpenPGP"),
    ("fido", "Autenticador FIDO U2F"),
    ("pkcs15", "Cartão PKCS#15 (certificado digital)"),
    ("ndef", "Tag NFC Forum Type 4"),
    ("globalplatform", "Java Card / GlobalPlatform"),
];

/// Lê uma base no formato do `smartcard_list.txt`: uma linha com o padrão do
/// ATR, seguida de linhas começando com TAB com as descrições; `#` comenta.
pub fn parse_list(text: &str, source: &'static str) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut current: Option<(String, Vec<String>)> = None;
    let mut flush = |cur: &mut Option<(String, Vec<String>)>| {
        if let Some((pattern, names)) = cur.take() {
            out.extend(Entry::new(&pattern, names, None, source));
        }
    };
    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with('\t') || line.starts_with(' ') {
            let desc = line.trim();
            if let (Some((_, names)), false) = (current.as_mut(), desc.is_empty()) {
                names.push(desc.to_string());
            }
        } else if line.trim().is_empty() {
            flush(&mut current);
        } else {
            flush(&mut current);
            current = Some((line.trim().to_string(), Vec::new()));
        }
    }
    flush(&mut current);
    out
}

/// Base em JSON: `[{"atr": "3B 8F 80 01 ..", "name": "...", "kind": "..."}]`.
pub fn parse_json(text: &str) -> Result<Vec<Entry>, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("invalid ATR database JSON: {e}"))?;
    let items = v.as_array().ok_or("ATR database JSON must be a list")?;
    let mut out = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let atr = item.get("atr").and_then(Value::as_str).ok_or_else(|| format!("entry {i}: 'atr' is required"))?;
        let name = item.get("name").and_then(Value::as_str).ok_or_else(|| format!("entry {i}: 'name' is required"))?;
        let kind = item.get("kind").and_then(Value::as_str).map(str::to_string);
        let e = Entry::new(atr, vec![name.to_string()], kind, "user").ok_or_else(|| format!("entry {i}: invalid ATR pattern '{atr}'"))?;
        out.push(e);
    }
    Ok(out)
}

/// Carrega uma base (`.json` = formato próprio, o resto = smartcard_list.txt)
/// e devolve quantas entradas foram acrescentadas.
pub fn load_file(path: &str) -> Result<usize, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let text = String::from_utf8_lossy(&bytes);
    let entries = if path.to_lowercase().ends_with(".json") { parse_json(&text)? } else { parse_list(&text, "list") };
    let n = entries.len();
    DB.write().unwrap().extend(entries);
    Ok(n)
}

pub fn clear() {
    DB.write().unwrap().clear();
}

pub fn count() -> usize {
    DB.read().unwrap().len()
}

/// Família de operações de leitura/escrita que o cartão aceita.
pub fn family(kind: &str) -> &'static str {
    match kind {
        "mifare_classic_1k" | "mifare_classic_4k" | "mifare_mini" | "mifare_plus_sl1" => "mifare_classic",
        "mifare_ultralight" | "mifare_ultralight_c" => "mifare_ultralight",
        "felica" | "jewel" | "topaz" | "icode_sli" | "mifare_plus_sl2" => "storage",
        "unknown" => "unknown",
        _ => "iso7816",
    }
}

/// Identifica um cartão pelo ATR. Ordem de precedência do nome: base do
/// usuário (JSON) > padrão PC/SC > tabela embutida > smartcard_list > heurística.
pub fn identify_atr(raw: &[u8]) -> Value {
    let atr = match Atr::parse(raw) {
        Ok(a) => a,
        Err(e) => {
            return json!({
                "atr": spaced(raw), "name": "ATR inválido", "kind": "unknown", "family": "unknown",
                "interface": "unknown", "confidence": "none", "source": "none", "matches": [], "error": e,
            });
        }
    };
    let text = spaced(raw);
    let mut out = Map::new();
    let (mut name, mut kind, mut confidence, mut source);
    let interface = if atr.contactless() { "contactless" } else { "contact" };

    let protocols = atr.protocols().iter().map(|t| format!("T={t}")).collect::<Vec<_>>().join("/");
    if atr.contactless() {
        (name, kind) = ("Cartão sem contato ISO 14443-4".to_string(), "iso14443_4".to_string());
    } else {
        (name, kind) = (format!("Cartão com chip ISO 7816 ({protocols})"), "iso7816".to_string());
    }
    (confidence, source) = ("low", "heuristic");

    if let Some(txt) = atr.historical_text() {
        let up = txt.to_uppercase();
        if let Some((_, n, k)) = KEYWORDS.iter().find(|(word, _, _)| up.contains(word)) {
            (name, kind, confidence) = (format!("{n} ({txt})"), k.to_string(), "medium");
        }
        out.insert("historical_text".into(), json!(txt));
    }

    let mut pcsc = false;
    if let Some((ss, nn)) = atr.storage() {
        pcsc = true;
        match card_name(nn) {
            Some((n, k)) => (name, kind) = (n.to_string(), k.to_string()),
            None => (name, kind) = (format!("Cartão de memória sem contato (código {nn:04X})"), "storage".to_string()),
        }
        (confidence, source) = ("high", "pcsc");
        out.insert(
            "storage".into(),
            json!({ "standard_code": ss, "standard": standard_name(ss), "card_code": format!("{nn:04X}") }),
        );
    }

    if !pcsc {
        for (pattern, n, k) in BUILTIN {
            if Entry::new(pattern, vec![], None, "builtin").is_some_and(|e| e.matches(&text)) {
                (name, kind, confidence, source) = (n.to_string(), k.to_string(), "high", "builtin");
            }
        }
    }

    let mut matches = Vec::new();
    let db = DB.read().unwrap();
    for e in db.iter().filter(|e| e.source == "list" && e.matches(&text)) {
        matches.extend(e.names.iter().cloned());
        if source == "heuristic"
            && let Some(first) = e.names.first() {
                (name, confidence, source) = (first.clone(), "medium", "list");
            }
    }
    for e in db.iter().filter(|e| e.source == "user" && e.matches(&text)) {
        if let Some(first) = e.names.first() {
            name = first.clone();
        }
        if let Some(k) = &e.kind {
            kind = k.clone();
        }
        (confidence, source) = ("exact", "user");
    }

    out.insert("atr".into(), json!(text));
    out.insert("name".into(), json!(name));
    out.insert("family".into(), json!(family(&kind)));
    out.insert("kind".into(), json!(kind));
    out.insert("interface".into(), json!(interface));
    out.insert("protocols".into(), json!(atr.protocols()));
    out.insert("confidence".into(), json!(confidence));
    out.insert("source".into(), json!(source));
    out.insert("matches".into(), json!(matches));
    Value::Object(out)
}

/// Complementa a identificação conversando com o cartão: UID (sem contato,
/// `FF CA`) e, para cartões com microprocessador, SELECT das aplicações
/// conhecidas. Só envia comandos de leitura (GET DATA, SELECT, READ RECORD).
pub fn probe(t: &mut dyn Transport, id: &mut Value) {
    let o = id.as_object_mut().unwrap();
    if o["interface"] == "contactless"
        && let Ok(r) = apdu::transmit(t, &[0xFF, 0xCA, 0x00, 0x00, 0x00], true)
            && r.ok() && !r.data.is_empty() {
                o.insert("uid".into(), json!(to_hex(&r.data)));
            }
    if o["family"] != "iso7816" {
        return;
    }
    let mut apps = Vec::new();
    let mut emv_labels = Vec::new();
    for (aid, label, kind) in AIDS {
        let aid_bytes = parse_hex(aid).unwrap();
        let Ok(cmd) = Apdu::new(0x00, 0xA4, 0x04, 0x00).data(&aid_bytes).le(256).encode() else { continue };
        let Ok(r) = apdu::transmit(t, &cmd, true) else { continue };
        if !r.ok() {
            continue;
        }
        let mut app = json!({ "aid": aid, "name": label, "kind": kind });
        if *kind == "emv" {
            let entries = emv_directory(t, &r.data);
            if !entries.is_empty() {
                for e in &entries {
                    if let Some(l) = e.get("label").and_then(Value::as_str)
                        && !emv_labels.contains(&l.to_string()) {
                            emv_labels.push(l.to_string());
                        }
                }
                app.as_object_mut().unwrap().insert("applications".into(), json!(entries));
            }
        }
        apps.push(app);
    }
    if apps.is_empty() {
        return;
    }
    let generic = o["source"] == "heuristic" && o["confidence"] == "low";
    if generic {
        for (k, n) in APP_NAMES {
            if apps.iter().any(|a| a["kind"] == *k) {
                let name = if *k == "emv" && !emv_labels.is_empty() { format!("{n} ({})", emv_labels.join(", ")) } else { n.to_string() };
                o.insert("name".into(), json!(name));
                o.insert("kind".into(), json!(k));
                o.insert("confidence".into(), json!("medium"));
                o.insert("source".into(), json!("probe"));
                break;
            }
        }
    }
    o.insert("applications".into(), json!(apps));
}

/// Aplicações de pagamento listadas no FCI do PPSE (direto) ou nos registros
/// do diretório do PSE (SFI do tag 88).
fn emv_directory(t: &mut dyn Transport, fci: &[u8]) -> Vec<Value> {
    let tlvs = parse_tlv(fci);
    let mut out = entries_of(&tlvs);
    let mut sfi = Vec::new();
    find_all(&tlvs, 0x88, &mut sfi);
    if let Some(sfi) = sfi.first().and_then(|s| s.value.first()) {
        for rec in 1..=16u8 {
            let Ok(r) = apdu::transmit(t, &[0x00, 0xB2, rec, (sfi << 3) | 4, 0x00], true) else { break };
            if !r.ok() {
                break;
            }
            out.extend(entries_of(&parse_tlv(&r.data)));
        }
    }
    out
}

/// Cada template 61 com `4F` (AID) e `50` (rótulo, ex. "VISA CREDITO").
fn entries_of(tlvs: &[apdu::Tlv]) -> Vec<Value> {
    let mut templates = Vec::new();
    find_all(tlvs, 0x61, &mut templates);
    templates
        .iter()
        .filter_map(|tpl| {
            let aid = tpl.children.iter().find(|c| c.tag == 0x4F)?;
            let label = tpl.children.iter().find(|c| c.tag == 0x50).map(|l| String::from_utf8_lossy(&l.value).trim().to_string());
            Some(json!({ "aid": to_hex(&aid.value), "label": label }))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apdu::tests::Mock;

    fn id(atr: &str) -> Value {
        identify_atr(&parse_hex(atr).unwrap())
    }

    // Os testes que mexem na base global rodam juntos neste, em sequência.
    #[test]
    fn identification() {
        clear();
        let c = id("3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 02 00 00 00 00 69");
        assert_eq!(c["name"], "MIFARE Classic 4K");
        assert_eq!(c["family"], "mifare_classic");
        assert_eq!(c["interface"], "contactless");
        assert_eq!(c["source"], "pcsc");

        let u = id("3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 03 00 00 00 00 68");
        assert_eq!(u["family"], "mifare_ultralight");

        assert_eq!(id("3B 81 80 01 80 80")["kind"], "desfire");
        assert_eq!(id("3B F8 13 00 00 81 31 FE 15 59 75 62 69 6B 65 79 34 D4")["kind"], "token");

        let g = id("3B 02 14 50");
        assert_eq!(g["source"], "heuristic");
        assert_eq!(g["family"], "iso7816");
        assert_eq!(id("3B 8F 80")["kind"], "unknown");

        let list = "# comentário\n3B 02 14 50\n\tSchlumberger Multiflex 3k\n\tsegunda linha\n\n3B 8F 80 01 80 4F 0C A0 00 00 03 06 .. 00 01 .. .. .. .. ..\n\tMifare Card Classic 1K\n";
        let entries = parse_list(list, "list");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].names, vec!["Schlumberger Multiflex 3k", "segunda linha"]);
        DB.write().unwrap().extend(entries);
        let g = id("3B 02 14 50");
        assert_eq!(g["name"], "Schlumberger Multiflex 3k");
        assert_eq!(g["source"], "list");
        // O padrão PC/SC continua dando o nome, a lista entra em matches.
        let c = id("3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 01 00 00 00 00 6A");
        assert_eq!(c["name"], "MIFARE Classic 1K");
        assert_eq!(c["matches"][0], "Mifare Card Classic 1K");

        let user = parse_json(r#"[{"atr": "3B 02 14 ..", "name": "Crachá da empresa", "kind": "badge"}]"#).unwrap();
        DB.write().unwrap().extend(user);
        let b = id("3B 02 14 50");
        assert_eq!(b["name"], "Crachá da empresa");
        assert_eq!(b["kind"], "badge");
        assert_eq!(b["source"], "user");
        assert!(parse_json(r#"[{"atr": "3B (", "name": "x"}]"#).is_err());
        clear();
        assert_eq!(count(), 0);
    }

    #[test]
    fn probe_emv_contactless() {
        let mut v = id("3B 8E 80 01 80 31 80 66 B1 84 0C 01 6E 01 83 00 90 00 1C");
        assert_eq!(v["family"], "iso7816");
        let ppse = "6F2C840E325041592E5359532E4444463031A51ABF0C1761154F07A0000000031010500A564953412044454249549000";
        let mut replies = vec!["04A1B2C39000", ppse];
        replies.extend(std::iter::repeat_n("6A82", AIDS.len() - 1));
        let mut m = Mock::new(&replies);
        probe(&mut m, &mut v);
        assert_eq!(v["uid"], "04A1B2C3");
        assert_eq!(v["kind"], "emv");
        assert_eq!(v["name"], "Cartão de pagamento EMV (VISA DEBIT)");
        assert_eq!(v["applications"][0]["applications"][0]["aid"], "A0000000031010");
    }

    #[test]
    fn probe_skips_memory_cards() {
        let mut v = id("3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 01 00 00 00 00 6A");
        let mut m = Mock::new(&["11223344 9000"]);
        probe(&mut m, &mut v);
        assert_eq!(v["uid"], "11223344");
        assert_eq!(m.sent.len(), 1);
    }
}
