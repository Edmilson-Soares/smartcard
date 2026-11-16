//! APDUs (ISO/IEC 7816-4): hex, montagem de comandos, respostas, status words,
//! BER-TLV e o transporte com GET RESPONSE automático.

use serde_json::{Value, json};

/// Converte hex em bytes. Aceita espaços, `:` e `-` entre os bytes.
pub fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace() && *b != b':' && *b != b'-').collect();
    if !digits.len().is_multiple_of(2) {
        return Err(format!("invalid hex (odd number of digits): {s}"));
    }
    digits
        .chunks(2)
        .map(|pair| {
            let txt = std::str::from_utf8(pair).map_err(|_| format!("invalid hex: {s}"))?;
            u8::from_str_radix(txt, 16).map_err(|_| format!("invalid hex: {s}"))
        })
        .collect()
}

/// Bytes em hex maiúsculo, sem separador: `3B8F80`.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Bytes em hex maiúsculo separado por espaço: `3B 8F 80` (formato dos ATRs).
pub fn spaced(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
}

/// Comando APDU. `le` vai de 1 a 65536 (256 é codificado `00` em formato curto).
#[derive(Debug, Clone, Default)]
pub struct Apdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
    pub le: Option<u32>,
}

impl Apdu {
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8) -> Apdu {
        Apdu { cla, ins, p1, p2, ..Default::default() }
    }

    pub fn data(mut self, data: &[u8]) -> Apdu {
        self.data = data.to_vec();
        self
    }

    pub fn le(mut self, le: u32) -> Apdu {
        self.le = Some(le);
        self
    }

    /// Codifica nos casos 1 a 4, curto ou estendido (estendido só quando
    /// `data` passa de 255 bytes ou `le` de 256).
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let lc = self.data.len();
        if lc > 65535 {
            return Err(format!("APDU data too long ({lc} bytes, max 65535)"));
        }
        if let Some(le) = self.le
            && (le == 0 || le > 65536) {
                return Err(format!("invalid Le {le} (1..=65536)"));
            }
        let extended = lc > 255 || self.le.is_some_and(|le| le > 256);
        let mut out = vec![self.cla, self.ins, self.p1, self.p2];
        if extended {
            out.push(0);
            if lc > 0 {
                out.extend_from_slice(&(lc as u16).to_be_bytes());
                out.extend_from_slice(&self.data);
            }
            if let Some(le) = self.le {
                out.extend_from_slice(&((le % 65536) as u16).to_be_bytes());
            }
        } else {
            if lc > 0 {
                out.push(lc as u8);
                out.extend_from_slice(&self.data);
            }
            if let Some(le) = self.le {
                out.push((le % 256) as u8);
            }
        }
        Ok(out)
    }

    /// `{"cla": 0, "ins": 164, "p1": 4, "p2": 0, "data": "A000...", "le": 256}`;
    /// `cla`, `p1`, `p2`, `data` e `le` são opcionais.
    pub fn from_json(v: &Value) -> Result<Apdu, String> {
        let byte = |key: &str, required: bool| -> Result<u8, String> {
            match v.get(key) {
                None | Some(Value::Null) if !required => Ok(0),
                Some(n) => n.as_u64().filter(|n| *n <= 255).map(|n| n as u8).ok_or_else(|| format!("APDU field '{key}' must be 0..=255")),
                None => Err(format!("APDU field '{key}' is required")),
            }
        };
        let data = match v.get("data") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::String(s)) => parse_hex(s)?,
            Some(_) => return Err("APDU field 'data' must be a hex string".into()),
        };
        let le = match v.get("le") {
            None | Some(Value::Null) => None,
            Some(n) => Some(n.as_u64().filter(|n| (1..=65536).contains(n)).ok_or("APDU field 'le' must be 1..=65536")? as u32),
        };
        let (mut p1, mut p2) = (byte("p1", false)?, byte("p2", false)?);
        // "p1p2": P1 e P2 juntos como um inteiro de 16 bits (offsets).
        if let Some(n) = v.get("p1p2").filter(|n| !n.is_null()) {
            let n = n.as_u64().filter(|n| *n <= 0xFFFF).ok_or("APDU field 'p1p2' must be 0..=65535")?;
            [p1, p2] = (n as u16).to_be_bytes();
        }
        Ok(Apdu { cla: byte("cla", false)?, ins: byte("ins", true)?, p1, p2, data, le })
    }
}

/// Resposta APDU: dados + SW1 SW2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub data: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

impl Response {
    pub fn from_raw(raw: &[u8]) -> Result<Response, String> {
        if raw.len() < 2 {
            return Err(format!("response too short ({} bytes): {}", raw.len(), to_hex(raw)));
        }
        let n = raw.len() - 2;
        Ok(Response { data: raw[..n].to_vec(), sw1: raw[n], sw2: raw[n + 1] })
    }

    pub fn sw(&self) -> u16 {
        u16::from_be_bytes([self.sw1, self.sw2])
    }

    /// 9000, ou 62xx/63xx (avisos com os dados retornados).
    pub fn ok(&self) -> bool {
        self.sw() == 0x9000
    }

    pub fn check(self) -> Result<Response, String> {
        if self.ok() { Ok(self) } else { Err(format!("card returned {:04X}: {}", self.sw(), sw_text(self.sw1, self.sw2))) }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "data": to_hex(&self.data),
            "sw": format!("{:04X}", self.sw()),
            "sw1": self.sw1,
            "sw2": self.sw2,
            "ok": self.ok(),
            "status": sw_text(self.sw1, self.sw2),
        })
    }
}

/// Significado de um status word (ISO/IEC 7816-4 e PC/SC parte 3).
pub fn sw_text(sw1: u8, sw2: u8) -> String {
    let s = match (sw1, sw2) {
        (0x90, 0x00) => "sucesso",
        (0x61, n) => return format!("{n} bytes disponíveis (GET RESPONSE)"),
        (0x62, 0x81) => "parte dos dados pode estar corrompida",
        (0x62, 0x82) => "fim do arquivo alcançado antes de ler Le bytes",
        (0x62, 0x83) => "arquivo selecionado invalidado",
        (0x62, 0x84) => "FCI fora do formato",
        (0x62, _) => "aviso: memória não alterada",
        (0x63, 0x00) => "verificação falhou",
        (0x63, n) if n & 0xF0 == 0xC0 => return format!("verificação falhou, {} tentativa(s) restante(s)", n & 0x0F),
        (0x63, _) => "aviso: memória alterada",
        (0x64, _) => "erro de execução, memória não alterada",
        (0x65, 0x81) => "falha de memória",
        (0x65, _) => "erro de execução, memória alterada",
        (0x67, 0x00) => "tamanho incorreto (Lc/Le)",
        (0x68, 0x81) => "canal lógico não suportado",
        (0x68, 0x82) => "secure messaging não suportado",
        (0x68, 0x83) => "último comando da cadeia esperado",
        (0x68, 0x84) => "encadeamento de comandos não suportado",
        (0x68, _) => "função do CLA não suportada",
        (0x69, 0x81) => "comando incompatível com a estrutura do arquivo",
        (0x69, 0x82) => "condição de segurança não satisfeita",
        (0x69, 0x83) => "método de autenticação bloqueado",
        (0x69, 0x84) => "dado de referência inutilizável",
        (0x69, 0x85) => "condições de uso não satisfeitas",
        (0x69, 0x86) => "comando não permitido (sem EF selecionado)",
        (0x69, 0x87) => "objetos de secure messaging ausentes",
        (0x69, 0x88) => "objetos de secure messaging incorretos",
        (0x69, _) => "comando não permitido",
        (0x6A, 0x80) => "parâmetros incorretos no campo de dados",
        (0x6A, 0x81) => "função não suportada",
        (0x6A, 0x82) => "arquivo ou aplicação não encontrado",
        (0x6A, 0x83) => "registro não encontrado",
        (0x6A, 0x84) => "memória insuficiente no arquivo",
        (0x6A, 0x86) => "P1/P2 incorretos",
        (0x6A, 0x88) => "dado referenciado não encontrado",
        (0x6A, 0x89) => "arquivo já existe",
        (0x6A, _) => "parâmetros P1/P2 incorretos",
        (0x6B, 0x00) => "P1/P2 incorretos (offset fora do EF)",
        (0x6C, n) => return format!("Le incorreto, o correto é {n}"),
        (0x6D, 0x00) => "INS não suportado",
        (0x6E, 0x00) => "CLA não suportado",
        (0x6F, 0x00) => "erro sem diagnóstico preciso",
        _ => "status desconhecido",
    };
    s.to_string()
}

/// Meio de enviar APDUs brutos a um cartão (PC/SC, ou um simulado nos testes).
pub trait Transport {
    fn exchange(&mut self, apdu: &[u8]) -> Result<Vec<u8>, String>;
}

/// Envia um APDU. Com `auto`, trata `6Cxx` (reenvia com o Le correto) e
/// `61xx` (busca o resto com GET RESPONSE, juntando os dados), como os
/// cartões T=0 exigem.
pub fn transmit(t: &mut dyn Transport, apdu: &[u8], auto: bool) -> Result<Response, String> {
    if apdu.len() < 4 {
        return Err(format!("APDU too short ({} bytes)", apdu.len()));
    }
    let mut resp = Response::from_raw(&t.exchange(apdu)?)?;
    if !auto {
        return Ok(resp);
    }
    if resp.sw1 == 0x6C
        && let Some(fixed) = with_le(apdu, resp.sw2) {
            resp = Response::from_raw(&t.exchange(&fixed)?)?;
        }
    let mut data = std::mem::take(&mut resp.data);
    let mut rounds = 0;
    while resp.sw1 == 0x61 {
        rounds += 1;
        if rounds > 256 {
            return Err("too many GET RESPONSE rounds".into());
        }
        // CLA sem o bit de encadeamento, mantendo o canal lógico.
        let get = [apdu[0] & !0x10, 0xC0, 0x00, 0x00, resp.sw2];
        resp = Response::from_raw(&t.exchange(&get)?)?;
        data.append(&mut resp.data);
    }
    resp.data = data;
    Ok(resp)
}

/// O mesmo APDU curto com Le trocado (ou acrescentado, no caso 3).
fn with_le(apdu: &[u8], le: u8) -> Option<Vec<u8>> {
    let mut a = apdu.to_vec();
    match apdu.len() {
        4 => a.push(le),
        5 => a[4] = le,
        n if apdu[4] != 0 && n == 5 + apdu[4] as usize => a.push(le),
        n if apdu[4] != 0 && n == 6 + apdu[4] as usize => a[n - 1] = le,
        _ => return None,
    }
    Some(a)
}

/// Objeto BER-TLV (ISO/IEC 8825-1, como usado em FCIs e EMV).
#[derive(Debug, Clone)]
pub struct Tlv {
    pub tag: u32,
    pub value: Vec<u8>,
    pub children: Vec<Tlv>,
}

/// Lê uma sequência BER-TLV; para no primeiro objeto malformado.
pub fn parse_tlv(mut data: &[u8]) -> Vec<Tlv> {
    let mut out = Vec::new();
    while let Some((tlv, rest)) = parse_one(data) {
        out.push(tlv);
        data = rest;
    }
    out
}

fn parse_one(data: &[u8]) -> Option<(Tlv, &[u8])> {
    // 00 e FF são preenchimento entre objetos.
    let start = data.iter().position(|b| *b != 0x00 && *b != 0xFF)?;
    let data = &data[start..];
    let first = data[0];
    let mut tag = first as u32;
    let mut i = 1;
    if first & 0x1F == 0x1F {
        loop {
            let b = *data.get(i)?;
            tag = (tag << 8) | b as u32;
            i += 1;
            if b & 0x80 == 0 || i > 4 {
                break;
            }
        }
    }
    let l0 = *data.get(i)?;
    i += 1;
    let len = if l0 < 0x80 {
        l0 as usize
    } else {
        let n = (l0 & 0x7F) as usize;
        if n == 0 || n > 3 {
            return None;
        }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | *data.get(i)? as usize;
            i += 1;
        }
        len
    };
    let value = data.get(i..i + len)?.to_vec();
    let children = if first & 0x20 != 0 { parse_tlv(&value) } else { Vec::new() };
    Some((Tlv { tag, value, children }, &data[i + len..]))
}

/// Todos os objetos com `tag`, em qualquer profundidade, em ordem.
pub fn find_all<'a>(tlvs: &'a [Tlv], tag: u32, out: &mut Vec<&'a Tlv>) {
    for t in tlvs {
        if t.tag == tag {
            out.push(t);
        }
        find_all(&t.children, tag, out);
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Cartão simulado: devolve as respostas na ordem e guarda os comandos.
    pub struct Mock {
        pub replies: VecDeque<Vec<u8>>,
        pub sent: Vec<Vec<u8>>,
    }

    impl Mock {
        pub fn new(replies: &[&str]) -> Mock {
            Mock { replies: replies.iter().map(|r| parse_hex(r).unwrap()).collect(), sent: Vec::new() }
        }

        pub fn sent_hex(&self) -> Vec<String> {
            self.sent.iter().map(|s| to_hex(s)).collect()
        }
    }

    impl Transport for Mock {
        fn exchange(&mut self, apdu: &[u8]) -> Result<Vec<u8>, String> {
            self.sent.push(apdu.to_vec());
            self.replies.pop_front().ok_or_else(|| "mock: no more replies".to_string())
        }
    }

    #[test]
    fn hex_roundtrip() {
        assert_eq!(parse_hex("3b 8f:80-01").unwrap(), vec![0x3B, 0x8F, 0x80, 0x01]);
        assert_eq!(to_hex(&[0x00, 0xAB]), "00AB");
        assert_eq!(spaced(&[0x3B, 0x02]), "3B 02");
        assert!(parse_hex("ABC").is_err());
        assert!(parse_hex("ZZ").is_err());
    }

    #[test]
    fn encode_cases() {
        assert_eq!(to_hex(&Apdu::new(0, 0xA4, 4, 0).encode().unwrap()), "00A40400");
        assert_eq!(to_hex(&Apdu::new(0, 0xB0, 0, 0).le(256).encode().unwrap()), "00B0000000");
        assert_eq!(to_hex(&Apdu::new(0, 0xA4, 4, 0).data(&[0xA0, 0x01]).le(256).encode().unwrap()), "00A4040002A00100");
        let big = vec![0x11; 300];
        let e = Apdu::new(0, 0xD6, 0, 0).data(&big).encode().unwrap();
        assert_eq!(&e[..7], &[0, 0xD6, 0, 0, 0, 0x01, 0x2C]);
        assert_eq!(e.len(), 7 + 300);
        assert_eq!(to_hex(&Apdu::new(0, 0xB0, 0, 0).le(65536).encode().unwrap()), "00B00000000000");
        assert!(Apdu::new(0, 0, 0, 0).le(0).encode().is_err());
    }

    #[test]
    fn from_json() {
        let v: Value = serde_json::from_str(r#"{"ins":164,"p1":4,"data":"A000000003","le":256}"#).unwrap();
        assert_eq!(to_hex(&Apdu::from_json(&v).unwrap().encode().unwrap()), "00A4040005A00000000300");
        assert!(Apdu::from_json(&serde_json::json!({"cla": 1})).is_err());
        let rb = Apdu::from_json(&serde_json::json!({"ins": 176, "p1p2": 300, "le": 16})).unwrap();
        assert_eq!(to_hex(&rb.encode().unwrap()), "00B0012C10");
        assert!(Apdu::from_json(&serde_json::json!({"ins": 300})).is_err());
    }

    #[test]
    fn get_response_chain() {
        let mut m = Mock::new(&["6105", "0102030405 6102", "0607 9000"]);
        let r = transmit(&mut m, &parse_hex("00A4040002A001").unwrap(), true).unwrap();
        assert_eq!(to_hex(&r.data), "01020304050607");
        assert!(r.ok());
        assert_eq!(m.sent_hex(), vec!["00A4040002A001", "00C0000005", "00C0000002"]);
    }

    #[test]
    fn wrong_le_is_retried() {
        let mut m = Mock::new(&["6C08", "1122334455667788 9000"]);
        let r = transmit(&mut m, &parse_hex("00CA9F1700").unwrap(), true).unwrap();
        assert_eq!(r.data.len(), 8);
        assert_eq!(m.sent_hex()[1], "00CA9F1708");
    }

    #[test]
    fn raw_mode_does_not_follow() {
        let mut m = Mock::new(&["6110"]);
        let r = transmit(&mut m, &parse_hex("00A40400").unwrap(), false).unwrap();
        assert_eq!(r.sw(), 0x6110);
        assert_eq!(m.sent.len(), 1);
    }

    #[test]
    fn sw_texts() {
        assert_eq!(sw_text(0x90, 0), "sucesso");
        assert!(sw_text(0x63, 0xC2).contains("2 tentativa"));
        assert_eq!(sw_text(0x6A, 0x82), "arquivo ou aplicação não encontrado");
    }

    #[test]
    fn tlv_nested() {
        // FCI de PPSE: 6F > A5 > BF0C > 61 > (4F, 50)
        let fci = parse_hex("6F2C 840E325041592E5359532E4444463031 A51A BF0C17 6115 4F07A0000000031010 500A56495341204445424954 9000").unwrap();
        let tlvs = parse_tlv(&fci[..fci.len() - 2]);
        let mut aids = Vec::new();
        find_all(&tlvs, 0x4F, &mut aids);
        assert_eq!(to_hex(&aids[0].value), "A0000000031010");
        let mut labels = Vec::new();
        find_all(&tlvs, 0x50, &mut labels);
        assert_eq!(String::from_utf8_lossy(&labels[0].value), "VISA DEBIT");
    }
}
