//! ATR (Answer To Reset): bytes de interface (ISO/IEC 7816-3), bytes
//! históricos (ISO/IEC 7816-4) e o ATR sintético dos leitores sem contato
//! (PC/SC parte 3).

use serde_json::{Map, Value, json};

use crate::apdu::{spaced, to_hex};

const FI: [u32; 16] = [372, 372, 558, 744, 1116, 1488, 1860, 0, 0, 512, 768, 1024, 1536, 2048, 0, 0];
const FMAX_KHZ: [u32; 16] = [4000, 5000, 6000, 8000, 12000, 16000, 20000, 0, 0, 5000, 7500, 10000, 15000, 20000, 0, 0];
const DI: [u32; 16] = [0, 1, 2, 4, 8, 16, 32, 64, 12, 20, 0, 0, 0, 0, 0, 0];

/// RID do PC/SC Workgroup, usado no ATR dos cartões de memória sem contato.
const PCSC_RID: [u8; 5] = [0xA0, 0x00, 0x00, 0x03, 0x06];

/// TAi, TBi, TCi e TDi de um grupo (i a partir de 1).
#[derive(Debug, Default, Clone, Copy)]
pub struct Group {
    pub ta: Option<u8>,
    pub tb: Option<u8>,
    pub tc: Option<u8>,
    pub td: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct Atr {
    pub raw: Vec<u8>,
    pub groups: Vec<Group>,
    pub historical: Vec<u8>,
    pub tck: Option<u8>,
    pub tck_ok: Option<bool>,
    pub warnings: Vec<String>,
}

impl Atr {
    pub fn parse(raw: &[u8]) -> Result<Atr, String> {
        if raw.len() < 2 {
            return Err(format!("ATR too short ({} bytes)", raw.len()));
        }
        let mut warnings = Vec::new();
        if raw[0] != 0x3B && raw[0] != 0x3F {
            warnings.push(format!("unexpected TS 0x{:02X} (expected 3B or 3F)", raw[0]));
        }
        if raw.len() > 33 {
            warnings.push(format!("ATR longer than 33 bytes ({})", raw.len()));
        }
        let t0 = raw[1];
        let mut y = t0 >> 4;
        let mut i = 2;
        let mut groups = Vec::new();
        loop {
            let mut g = Group::default();
            for (bit, slot) in [(1u8, &mut g.ta), (2, &mut g.tb), (4, &mut g.tc), (8, &mut g.td)] {
                if y & bit != 0 {
                    *slot = Some(*raw.get(i).ok_or("ATR truncated in interface bytes")?);
                    i += 1;
                }
            }
            groups.push(g);
            match g.td {
                Some(td) => y = td >> 4,
                None => break,
            }
        }
        let k = (t0 & 0x0F) as usize;
        let historical = raw.get(i..i + k).ok_or("ATR truncated in historical bytes")?.to_vec();
        i += k;
        let mut atr = Atr { raw: raw.to_vec(), groups, historical, tck: None, tck_ok: None, warnings };
        // TCK existe quando algum TDi indica um protocolo diferente de T=0.
        if atr.indicated().iter().any(|t| *t != 0) {
            match raw.get(i) {
                Some(&tck) => {
                    i += 1;
                    let ok = raw[1..i].iter().fold(0, |acc, b| acc ^ b) == 0;
                    atr.tck = Some(tck);
                    atr.tck_ok = Some(ok);
                    if !ok {
                        atr.warnings.push("TCK checksum mismatch".into());
                    }
                }
                None => atr.warnings.push("TCK missing".into()),
            }
        }
        if i < raw.len() {
            atr.warnings.push(format!("{} extra byte(s) after the ATR", raw.len() - i));
        }
        Ok(atr)
    }

    /// Valores T indicados nos TDi, em ordem (pode incluir 15).
    fn indicated(&self) -> Vec<u8> {
        self.groups.iter().filter_map(|g| g.td.map(|td| td & 0x0F)).collect()
    }

    /// Protocolos de transmissão oferecidos (T=0 quando nenhum é indicado).
    pub fn protocols(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for t in self.indicated() {
            if t != 15 && !out.contains(&t) {
                out.push(t);
            }
        }
        if out.is_empty() {
            out.push(0);
        }
        out
    }

    /// Primeiro grupo de bytes específicos de T=`t` (os que vêm depois de um
    /// TDi com i >= 2 indicando esse T).
    fn specific(&self, t: u8) -> Option<&Group> {
        self.groups.get(1..)?.windows(2).find(|w| w[0].td.map(|td| td & 0x0F) == Some(t)).map(|w| &w[1])
    }

    /// ATR sintético de leitor sem contato: `3B 8n 80 01 <históricos> TCK`.
    pub fn contactless(&self) -> bool {
        let r = &self.raw;
        r.len() >= 4 && r[0] == 0x3B && r[1] >> 4 == 0x8 && r[2] == 0x80 && r[3] == 0x01
    }

    /// Cartão de memória sem contato (PC/SC parte 3): `(padrão SS, nome NN NN)`.
    pub fn storage(&self) -> Option<(u8, u16)> {
        let h = &self.historical;
        if h.len() >= 11 && h[0] == 0x80 && h[1] == 0x4F && h[3..8] == PCSC_RID {
            return Some((h[8], u16::from_be_bytes([h[9], h[10]])));
        }
        None
    }

    /// Maior trecho de texto ASCII (4+ caracteres) nos bytes históricos.
    /// Muitos cartões trazem ali o nome: "JCOP41V22", "Yubikey 4"...
    pub fn historical_text(&self) -> Option<String> {
        self.historical
            .split(|b| !(0x20..0x7F).contains(b))
            .map(|run| String::from_utf8_lossy(run).trim().to_string())
            .filter(|s| s.chars().filter(|c| c.is_ascii_alphanumeric()).count() >= 4)
            .max_by_key(|s| s.len())
    }

    pub fn to_json(&self) -> Value {
        let g1 = self.groups.first().copied().unwrap_or_default();
        let ta1 = g1.ta.unwrap_or(0x11);
        let (fi, di, fmax) = (FI[(ta1 >> 4) as usize], DI[(ta1 & 0x0F) as usize], FMAX_KHZ[(ta1 >> 4) as usize]);
        let mut interface = Map::new();
        for (n, g) in self.groups.iter().enumerate() {
            for (name, b) in [("TA", g.ta), ("TB", g.tb), ("TC", g.tc), ("TD", g.td)] {
                if let Some(b) = b {
                    interface.insert(format!("{name}{}", n + 1), json!(format!("{b:02X}")));
                }
            }
        }
        let mut out = json!({
            "atr": spaced(&self.raw),
            "hex": to_hex(&self.raw),
            "convention": if self.raw[0] == 0x3F { "inverse" } else { "direct" },
            "protocols": self.protocols(),
            "fi": nonzero(fi),
            "di": nonzero(di),
            "fmax_mhz": if fmax > 0 { json!(fmax as f64 / 1000.0) } else { Value::Null },
            "etu_clocks": if fi > 0 && di > 0 { json!(fi as f64 / di as f64) } else { Value::Null },
            "guard_time": g1.tc.unwrap_or(0),
            "interface_bytes": interface,
            "historical": to_hex(&self.historical),
            "historical_text": self.historical_text(),
            "historical_info": historical_json(&self.historical),
            "tck": self.tck.map(|b| format!("{b:02X}")),
            "tck_ok": self.tck_ok,
            "contactless": self.contactless(),
            "warnings": self.warnings,
        });
        let o = out.as_object_mut().unwrap();
        // TA2 presente = modo específico (sem PPS), com o protocolo fixado.
        if let Some(ta2) = self.groups.get(1).and_then(|g| g.ta) {
            o.insert("specific_mode".into(), json!({ "protocol": ta2 & 0x0F, "can_change": ta2 & 0x80 == 0 }));
        }
        if let Some(t1) = self.specific(1) {
            let tb = t1.tb.unwrap_or(0x4D);
            o.insert(
                "t1".into(),
                json!({
                    "ifsc": t1.ta.unwrap_or(32),
                    "bwi": tb >> 4,
                    "cwi": tb & 0x0F,
                    "checksum": if t1.tc.unwrap_or(0) & 1 == 1 { "CRC" } else { "LRC" },
                }),
            );
        }
        if let Some(ta) = self.specific(15).and_then(|g| g.ta) {
            let classes: Vec<&str> =
                [(1, "A (5V)"), (2, "B (3V)"), (4, "C (1.8V)")].iter().filter(|(bit, _)| ta & bit != 0).map(|(_, n)| *n).collect();
            o.insert("voltage_classes".into(), json!(classes));
        }
        if let Some((ss, nn)) = self.storage() {
            o.insert("storage".into(), storage_json(ss, nn));
        }
        out
    }
}

fn nonzero(v: u32) -> Value {
    if v == 0 { Value::Null } else { json!(v) }
}

/// Padrão SS do ATR PC/SC parte 3.
pub fn standard_name(ss: u8) -> Option<&'static str> {
    Some(match ss {
        0x01 => "ISO 14443 A, parte 1",
        0x02 => "ISO 14443 A, parte 2",
        0x03 => "ISO 14443 A, parte 3",
        0x05 => "ISO 14443 B, parte 1",
        0x06 => "ISO 14443 B, parte 2",
        0x07 => "ISO 14443 B, parte 3",
        0x09 => "ISO 15693, parte 1",
        0x0A => "ISO 15693, parte 2",
        0x0B => "ISO 15693, parte 3",
        0x0C => "ISO 15693, parte 4",
        0x0D => "ISO 7816-10 (I2C)",
        0x0E => "ISO 7816-10 (I2C estendido)",
        0x0F => "ISO 7816-10 (2WBP)",
        0x10 => "ISO 7816-10 (3WBP)",
        0x11 => "FeliCa",
        _ => return None,
    })
}

/// Nome NN NN do ATR PC/SC parte 3: `(nome, tipo)`.
pub fn card_name(nn: u16) -> Option<(&'static str, &'static str)> {
    Some(match nn {
        0x0001 => ("MIFARE Classic 1K", "mifare_classic_1k"),
        0x0002 => ("MIFARE Classic 4K", "mifare_classic_4k"),
        0x0003 => ("MIFARE Ultralight / NTAG", "mifare_ultralight"),
        0x0026 => ("MIFARE Mini", "mifare_mini"),
        0x0036 => ("MIFARE Plus SL1 2K", "mifare_plus_sl1"),
        0x0037 => ("MIFARE Plus SL1 4K", "mifare_plus_sl1"),
        0x0038 => ("MIFARE Plus SL2 2K", "mifare_plus_sl2"),
        0x0039 => ("MIFARE Plus SL2 4K", "mifare_plus_sl2"),
        0x003A => ("MIFARE Ultralight C", "mifare_ultralight_c"),
        0x003B => ("FeliCa", "felica"),
        0x002F => ("Innovision Jewel", "jewel"),
        0x0030 => ("Topaz (NFC Forum Type 1)", "topaz"),
        0x0014 => ("NXP ICODE SLI", "icode_sli"),
        _ => return None,
    })
}

fn storage_json(ss: u8, nn: u16) -> Value {
    json!({
        "standard_code": ss,
        "standard": standard_name(ss),
        "card_code": format!("{nn:04X}"),
        "card": card_name(nn).map(|(n, _)| n),
    })
}

/// Bytes históricos (ISO/IEC 7816-4, 8.1.1): indicador de categoria +
/// objetos COMPACT-TLV.
pub fn historical_json(h: &[u8]) -> Value {
    if h.is_empty() {
        return Value::Null;
    }
    match h[0] {
        0x80 if h.get(1) == Some(&0x4F) => json!({ "category": "pcsc_storage" }),
        0x80 => json!({ "category": "compact_tlv", "objects": compact_tlv(&h[1..]) }),
        0x00 if h.len() >= 4 => {
            let (body, status) = h[1..].split_at(h.len() - 4);
            json!({ "category": "compact_tlv_status", "objects": compact_tlv(body), "status": to_hex(status) })
        }
        0x10 if h.len() >= 2 => json!({ "category": "dir_reference", "reference": format!("{:02X}", h[1]) }),
        _ => json!({ "category": "proprietary" }),
    }
}

fn compact_tlv(data: &[u8]) -> Vec<Value> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let tag = data[i] >> 4;
        let len = (data[i] & 0x0F) as usize;
        i += 1;
        let Some(v) = data.get(i..i + len) else { break };
        i += len;
        let name = match tag {
            0x1 => "country_code",
            0x2 => "issuer_id",
            0x3 => "card_service_data",
            0x4 => "initial_access_data",
            0x5 => "card_issuer_data",
            0x6 => "pre_issuing_data",
            0x7 => "card_capabilities",
            0x8 => "status",
            0xF => "application_id",
            _ => "rfu",
        };
        let mut obj = json!({ "tag": tag, "name": name, "value": to_hex(v) });
        if tag == 0x7 && v.len() >= 3 {
            let o = obj.as_object_mut().unwrap();
            o.insert("command_chaining".into(), json!(v[2] & 0x80 != 0));
            o.insert("extended_length".into(), json!(v[2] & 0x40 != 0));
            o.insert("logical_channels".into(), json!((v[2] & 0x07) + 1));
        }
        out.push(obj);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apdu::parse_hex;

    fn atr(s: &str) -> Atr {
        Atr::parse(&parse_hex(s).unwrap()).unwrap()
    }

    #[test]
    fn mifare_classic_1k() {
        let a = atr("3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 01 00 00 00 00 6A");
        assert!(a.contactless());
        assert_eq!(a.storage(), Some((0x03, 0x0001)));
        assert_eq!(a.tck_ok, Some(true));
        assert_eq!(a.protocols(), vec![0, 1]);
        assert!(a.warnings.is_empty());
        let j = a.to_json();
        assert_eq!(j["storage"]["card"], "MIFARE Classic 1K");
        assert_eq!(j["storage"]["standard"], "ISO 14443 A, parte 3");
    }

    #[test]
    fn contact_t1_with_tck() {
        // YubiKey 4 (CCID): T=1, nome nos bytes históricos.
        let a = atr("3B F8 13 00 00 81 31 FE 15 59 75 62 69 6B 65 79 34 D4");
        assert_eq!(a.protocols(), vec![1]);
        assert_eq!(a.tck_ok, Some(true));
        assert_eq!(a.historical_text().as_deref(), Some("Yubikey4"));
        let j = a.to_json();
        assert_eq!(j["fi"], 372);
        assert_eq!(j["di"], 4);
        assert_eq!(j["t1"]["ifsc"], 0xFE);
        assert_eq!(j["interface_bytes"]["TD2"], "31");
    }

    #[test]
    fn t0_without_tck() {
        // Só T=0 implícito: sem TCK.
        let a = atr("3B 02 14 50");
        assert_eq!(a.protocols(), vec![0]);
        assert_eq!(a.tck, None);
        assert_eq!(a.historical, vec![0x14, 0x50]);
        assert!(a.warnings.is_empty());
    }

    #[test]
    fn bad_checksum_and_truncation() {
        let a = atr("3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 01 00 00 00 00 6B");
        assert_eq!(a.tck_ok, Some(false));
        assert!(Atr::parse(&parse_hex("3B 8F 80 01 80").unwrap()).is_err());
        assert!(Atr::parse(&[0x3B]).is_err());
    }

    #[test]
    fn compact_tlv_capabilities() {
        // Categoria 80, card capabilities 73 com chaining + extended length.
        let j = historical_json(&parse_hex("80 31 80 73 00 00 C0").unwrap());
        let objs = j["objects"].as_array().unwrap();
        let caps = objs.iter().find(|o| o["name"] == "card_capabilities").unwrap();
        assert_eq!(caps["extended_length"], true);
        assert_eq!(caps["command_chaining"], true);
    }
}
