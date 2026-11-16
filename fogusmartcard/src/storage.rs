//! Cartões de memória sem contato pelos pseudo-APDUs do PC/SC parte 3
//! (`FF 82` load key, `FF 86` authenticate, `FF B0` read, `FF D6` update),
//! que funcionam em praticamente todo leitor PC/SC sem contato
//! (ACS ACR122/ACR1252, HID Omnikey, Identiv, Feitian...).

use crate::apdu::{self, Apdu, Response, Transport};

pub const DEFAULT_KEY: [u8; 6] = [0xFF; 6];
pub const KEY_A: u8 = 0x60;
pub const KEY_B: u8 = 0x61;

fn send(t: &mut dyn Transport, cmd: Apdu) -> Result<Response, String> {
    apdu::transmit(t, &cmd.encode()?, true)
}

/// UID do cartão sem contato (`FF CA 00 00 00`).
pub fn uid(t: &mut dyn Transport) -> Result<Vec<u8>, String> {
    Ok(send(t, Apdu::new(0xFF, 0xCA, 0x00, 0x00).le(256))?.check()?.data)
}

/// Grava a chave no slot do leitor. Tenta memória volátil (P1=00, ACS e a
/// maioria) e, se o leitor recusar, a não volátil (P1=20, Omnikey).
pub fn load_key(t: &mut dyn Transport, slot: u8, key: &[u8]) -> Result<(), String> {
    if key.len() != 6 {
        return Err(format!("MIFARE key must have 6 bytes, got {}", key.len()));
    }
    let r = send(t, Apdu::new(0xFF, 0x82, 0x00, slot).data(key))?;
    if r.ok() {
        return Ok(());
    }
    send(t, Apdu::new(0xFF, 0x82, 0x20, slot).data(key))?.check().map(|_| ()).map_err(|e| format!("load key failed: {e}"))
}

/// Autentica o bloco com a chave (A ou B) já carregada no slot. Usa o
/// GENERAL AUTHENTICATE (`FF 86`) e, em leitores antigos que não o têm,
/// o formato obsoleto `FF 88`.
pub fn authenticate(t: &mut dyn Transport, block: u16, key_type: u8, slot: u8) -> Result<(), String> {
    let [msb, lsb] = block.to_be_bytes();
    let r = send(t, Apdu::new(0xFF, 0x86, 0x00, 0x00).data(&[0x01, msb, lsb, key_type, slot]))?;
    if r.ok() {
        return Ok(());
    }
    if matches!(r.sw(), 0x6D00 | 0x6E00 | 0x6A81 | 0x6B00) {
        // FF 88 00 <bloco> <tipo> <slot>: o tipo ocupa o lugar do Lc.
        let r = apdu::transmit(t, &[0xFF, 0x88, 0x00, lsb, key_type, slot], true)?;
        if r.ok() {
            return Ok(());
        }
        return Err(auth_error(block, &r));
    }
    Err(auth_error(block, &r))
}

fn auth_error(block: u16, r: &Response) -> String {
    format!("authentication of block {block} failed ({:04X}): wrong key or access bits", r.sw())
}

pub fn read_binary(t: &mut dyn Transport, addr: u16, len: u16) -> Result<Vec<u8>, String> {
    let [msb, lsb] = addr.to_be_bytes();
    let r = send(t, Apdu::new(0xFF, 0xB0, msb, lsb).le(len.clamp(1, 256) as u32))?;
    r.check().map(|r| r.data).map_err(|e| format!("read of block/page {addr} failed: {e}"))
}

pub fn update_binary(t: &mut dyn Transport, addr: u16, data: &[u8]) -> Result<(), String> {
    let [msb, lsb] = addr.to_be_bytes();
    send(t, Apdu::new(0xFF, 0xD6, msb, lsb).data(data))?
        .check()
        .map(|_| ())
        .map_err(|e| format!("write of block/page {addr} failed: {e}"))
}

// ---- MIFARE Classic ----------------------------------------------------

/// Setores 0..31 têm 4 blocos; 32..39 (só no 4K) têm 16.
pub fn sector_of(block: u16) -> u16 {
    if block < 128 { block / 4 } else { 32 + (block - 128) / 16 }
}

pub fn first_block(sector: u16) -> u16 {
    if sector < 32 { sector * 4 } else { 128 + (sector - 32) * 16 }
}

pub fn blocks_in(sector: u16) -> u16 {
    if sector < 32 { 4 } else { 16 }
}

/// Último bloco do setor: chaves A/B e bits de acesso.
pub fn is_trailer(block: u16) -> bool {
    let s = sector_of(block);
    block == first_block(s) + blocks_in(s) - 1
}

/// Confere a redundância dos bits de acesso (bytes 6..8 do trailer): cada
/// bit C1/C2/C3 aparece também invertido. Um trailer com bits inconsistentes
/// bloqueia o setor para sempre.
pub fn access_bits_valid(trailer: &[u8]) -> bool {
    if trailer.len() != 16 {
        return false;
    }
    let (b6, b7, b8) = (trailer[6], trailer[7], trailer[8]);
    let (c1, c2, c3) = (b7 >> 4, b8 & 0x0F, b8 >> 4);
    (b6 & 0x0F) == (!c1 & 0x0F) && (b6 >> 4) == (!c2 & 0x0F) && (b7 & 0x0F) == (!c3 & 0x0F)
}

fn key_type(kind: i32) -> Result<u8, String> {
    match kind {
        0 => Ok(KEY_A),
        1 => Ok(KEY_B),
        _ => Err(format!("key type must be 0 (A) or 1 (B), got {kind}")),
    }
}

/// Carrega a chave no slot 0 e autentica o setor do bloco.
pub fn login(t: &mut dyn Transport, block: u16, key: &[u8], kind: i32) -> Result<(), String> {
    load_key(t, 0, key)?;
    authenticate(t, block, key_type(kind)?, 0)
}

pub fn classic_read(t: &mut dyn Transport, block: u16, key: &[u8], kind: i32) -> Result<Vec<u8>, String> {
    login(t, block, key, kind)?;
    read_binary(t, block, 16)
}

pub fn classic_read_sector(t: &mut dyn Transport, sector: u16, key: &[u8], kind: i32) -> Result<Vec<Vec<u8>>, String> {
    if sector >= 40 {
        return Err(format!("sector {sector} out of range (0..=39)"));
    }
    let first = first_block(sector);
    login(t, first, key, kind)?;
    (first..first + blocks_in(sector)).map(|b| read_binary(t, b, 16)).collect()
}

/// Regras de segurança da gravação de um bloco MIFARE Classic. O bloco 0
/// (UID/fabricante) e os trailers só são gravados com `allow_unsafe`, e
/// mesmo assim um trailer com bits de acesso inválidos é recusado.
pub fn check_classic_write(block: u16, data: &[u8], allow_unsafe: bool) -> Result<(), String> {
    if data.len() != 16 {
        return Err(format!("MIFARE Classic blocks have 16 bytes, got {}", data.len()));
    }
    if block >= 256 {
        return Err(format!("block {block} out of range (0..=255)"));
    }
    if block == 0 && !allow_unsafe {
        return Err("block 0 is the manufacturer block (UID); pass unsafe to write it".into());
    }
    if is_trailer(block) {
        if !allow_unsafe {
            return Err(format!("block {block} is the sector trailer (keys and access bits); pass unsafe to write it"));
        }
        if !access_bits_valid(data) {
            return Err(format!("refusing to write trailer {block}: inconsistent access bits would lock the sector forever"));
        }
    }
    Ok(())
}

pub fn classic_write(t: &mut dyn Transport, block: u16, data: &[u8], key: &[u8], kind: i32, allow_unsafe: bool) -> Result<(), String> {
    check_classic_write(block, data, allow_unsafe)?;
    login(t, block, key, kind)?;
    update_binary(t, block, data)
}

// ---- MIFARE Ultralight / NTAG -----------------------------------------

/// Páginas 0..3 guardam UID, bits de lock e OTP; gravar nelas é irreversível.
pub fn check_ultralight_write(page: u16, data: &[u8], allow_unsafe: bool) -> Result<(), String> {
    if data.is_empty() || !data.len().is_multiple_of(4) {
        return Err(format!("Ultralight writes are in 4-byte pages, got {} bytes", data.len()));
    }
    if page < 4 && !allow_unsafe {
        return Err(format!("page {page} holds UID/lock/OTP bits (irreversible); pass unsafe to write it"));
    }
    Ok(())
}

/// Grava `data` a partir de `page`, uma página (4 bytes) por comando.
pub fn ultralight_write(t: &mut dyn Transport, page: u16, data: &[u8], allow_unsafe: bool) -> Result<(), String> {
    check_ultralight_write(page, data, allow_unsafe)?;
    for (i, chunk) in data.chunks(4).enumerate() {
        update_binary(t, page + i as u16, chunk)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apdu::parse_hex;
    use crate::apdu::tests::Mock;

    #[test]
    fn layout() {
        assert!(is_trailer(3));
        assert!(is_trailer(63));
        assert!(!is_trailer(4));
        assert!(is_trailer(143));
        assert!(!is_trailer(131));
        assert!(is_trailer(255));
        assert_eq!(sector_of(130), 32);
        assert_eq!(first_block(39), 240);
    }

    #[test]
    fn transport_trailer_is_valid() {
        // Bits de acesso de fábrica: FF 07 80 69.
        let t = parse_hex("FFFFFFFFFFFF FF078069 FFFFFFFFFFFF").unwrap();
        assert!(access_bits_valid(&t));
        let mut broken = t.clone();
        broken[7] = 0x00;
        assert!(!access_bits_valid(&broken));
    }

    #[test]
    fn write_guards() {
        let data = [0u8; 16];
        assert!(check_classic_write(4, &data, false).is_ok());
        assert!(check_classic_write(0, &data, false).is_err());
        assert!(check_classic_write(7, &data, false).is_err());
        assert!(check_classic_write(7, &data, true).is_err()); // bits inválidos
        let trailer = parse_hex("FFFFFFFFFFFF FF078069 FFFFFFFFFFFF").unwrap();
        assert!(check_classic_write(7, &trailer, true).is_ok());
        assert!(check_classic_write(4, &[0u8; 15], false).is_err());
        assert!(check_ultralight_write(4, &[0; 8], false).is_ok());
        assert!(check_ultralight_write(2, &[0; 4], false).is_err());
        assert!(check_ultralight_write(4, &[0; 5], false).is_err());
    }

    #[test]
    fn classic_read_flow() {
        let mut m = Mock::new(&["9000", "9000", "000102030405060708090A0B0C0D0E0F 9000"]);
        let data = classic_read(&mut m, 4, &DEFAULT_KEY, 0).unwrap();
        assert_eq!(data.len(), 16);
        assert_eq!(m.sent_hex(), vec!["FF82000006FFFFFFFFFFFF", "FF860000050100046000", "FFB0000410"]);
    }

    #[test]
    fn fallbacks_for_older_readers() {
        // Load key volátil recusado, depois FF 86 não suportado -> FF 88.
        let mut m = Mock::new(&["6300", "9000", "6D00", "9000"]);
        login(&mut m, 8, &DEFAULT_KEY, 1).unwrap();
        assert_eq!(m.sent_hex(), vec!["FF82000006FFFFFFFFFFFF", "FF82200006FFFFFFFFFFFF", "FF860000050100086100", "FF8800086100"]);
    }

    #[test]
    fn auth_failure_message() {
        let mut m = Mock::new(&["9000", "6300"]);
        let e = login(&mut m, 4, &DEFAULT_KEY, 0).unwrap_err();
        assert!(e.contains("wrong key"));
    }

    #[test]
    fn ultralight_pages() {
        let mut m = Mock::new(&["9000", "9000"]);
        ultralight_write(&mut m, 4, &parse_hex("0102030405060708").unwrap(), false).unwrap();
        assert_eq!(m.sent_hex(), vec!["FFD600040401020304", "FFD600050405060708"]);
    }
}
