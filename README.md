# smartcard — leitura, gravação e reconhecimento de smart cards para Fogu

Uma lib Rust (`fogusmartcard`) com API C, mais um módulo Fogu (`scard.fg`) que a usa via
`fogu:ffi`. Fala PC/SC, então funciona com qualquer leitor que o sistema reconheça
(com e sem contato: ACS ACR38/ACR122/ACR1252, HID Omnikey, Identiv/SCM, Gemalto, Feitian,
leitores de token USB...), no Windows (WinSCard), Linux (pcsc-lite) e macOS.

```
fogusmartcard/  lib Rust (cdylib) com a API C
native/         fogusmartcard.dll / libfogusmartcard.so / .dylib (gerado pelo build)
scard.fg        wrapper Fogu: open(), Context, Card
scard.test.fg   testes (fogu test)
main.fg         exemplo: espera um cartão, reconhece e lê
examples/       pessoa.fg: grava/lê/apaga um registro pessoal (registro.fg + testes)
cards.json      exemplo de base de ATRs própria
atrlist.ps1/sh  baixa a base de ATRs do pcsc-tools para data/
```

<!-- fogu:plataformas -->
## Plataformas, binários e pré-requisitos

Ao importar `scard.fg`, a lib reconhece o sistema e a arquitetura
(`system.info.os`/`arch`) e já carrega o binário certo — `.dll` no Windows,
`.so` no Linux, `.dylib` no macOS. Se ele faltar, o programa não para no `import`:
o erro (com a lista de caminhos tentados) volta na primeira chamada que precisar da lib.
`nativeInfo()` mostra o que foi detectado: `{ platform, os, file, path, loaded, error }`.

| Plataforma | Arquivo | Neste repositório |
|---|---|---|
| `windows-x64` | `native/windows-x64/fogusmartcard.dll` | incluído |
| `windows-arm64` | `native/windows-arm64/fogusmartcard.dll` | — |
| `linux-x64` | `native/linux-x64/libfogusmartcard.so` | incluído |
| `linux-arm64` | `native/linux-arm64/libfogusmartcard.so` | incluído |
| `macos-x64` | `native/macos-x64/libfogusmartcard.dylib` | incluído |
| `macos-arm64` | `native/macos-arm64/libfogusmartcard.dylib` | incluído |

**Instalação** (Fogu 0.8.0+): `fogu add Edmilson-Soares/smartcard@^0.2.0`. Os binários de `native/` vão
no repositório git, então a lib já funciona depois de instalada — sem Rust/cargo na máquina.

Ordem de busca: o caminho passado a `load(path)`, a variável `FOGU_SMARTCARD_LIB`,
`native/<plataforma>/`, `native/` e o build do cargo no projeto em execução, uma
cópia em `fogu_modules/` e os pacotes instalados com `fogu add` (`$FOGU_HOME/fogu_modules`).

**Pré-requisitos**

- **Windows**: nada (usa o `winscard.dll` do sistema).
- **Linux**: serviço PC/SC rodando e a lib em tempo de execução: `sudo apt install pcscd libpcsclite1`. Para compilar o `.so`: `sudo apt install libpcsclite-dev` e `sh build.sh`.
- **macOS**: o `.dylib` precisa ser compilado num Mac (`sh build.sh` lá): linka o `PCSC.framework` do SDK da Apple.

**Gerar os binários**

```sh
fogu run build:native        # Windows: native/windows-<arch>/ (build.ps1)
sh build.sh                  # Linux/macOS/WSL: o sistema atual
sh build.sh all              # Linux x64/arm64 e macOS x64/arm64 (cargo-zigbuild + zig)
```

## Callbacks do fogu:ffi (requer Fogu 0.8.0+)

A camada nativa usa `ffi.callback` (veja `_native.fg`, igual em todas as libs deste repositório):

- **Sink de saída**: a lib recebe um callback uma vez (`*_set_sink`) e, chamada com
  `buf = nil, cap = 0`, entrega a resposta inteira por ele. As funções antigas, com buffer
  do chamador, continuam exportadas e funcionando (API C compatível).
- **Regras do fogu:ffi respeitadas**: um callback só roda na thread do interpretador, durante
  uma chamada FFI — as threads da lib nunca chamam o Fogu; elas enfileiram e a chamada
  `*_dispatch`/leitura entrega na thread de quem chamou. Um erro dentro de um callback derruba o
  programa, então o callback só guarda os dados e os handlers do usuário rodam depois, fora
  do frame nativo (com `?`, erros e `sleep` normais).
- **Esperas cooperativas**: uma chamada FFI bloqueante congela todas as tarefas `fg`, então as
  esperas longas são feitas em fatias de 10 ms com `time.delay(1ms)` entre elas (o mesmo
  padrão do pacote oficial `hardware`).

As respostas (leitores, eventos, APDUs, ATR) chegam inteiras pelo **sink** (`fsc_set_sink`), sem buffer fixo nem a segunda chamada de `fsc_pending`. `wait()`/`waitForCard()` esperam em fatias de 10 ms e cedem a vez entre elas: outras tarefas `fg` continuam rodando enquanto se espera um cartão (antes, `wait(-1)` congelava o programa inteiro). `scard.setCooperative(false)` volta à espera direta na lib.
- **Fogu 0.7.4+** (e 0.8.0): o código compilado chama direto as funções FFI de assinatura numérica (sem
  alocação por chamada), então sondar status/eventos num laço é barato; `fogu .` roda o projeto
  (o script `start` do `fogu.json`); os tipos `int32`, `uint8`, `float64`... valem nas assinaturas.
<!-- /fogu:plataformas -->

## Build e execução

```sh
fogu run build:native       # ou ./build.ps1 (Windows) / ./build.sh (Linux/macOS)
fogu run atrlist            # opcional: base com ~5000 modelos de cartão
fogu run main.fg
fogu test
cd fogusmartcard && cargo test  # testes da lib Rust (sem leitor, com cartão simulado)
```

Requer Rust ≥ 1.85 (edition 2024). No Linux: `apt install libpcsclite-dev pcscd` (e o
serviço `pcscd` rodando). No Windows e no macOS o PC/SC já vem no sistema.

```fogu
import scard from "./scard.fg"

fn main() {
    const ctx = scard.open()?
    const ev = ctx.waitForCard("", 30s)?          // nil se o tempo acabar
    const card = ctx.connect(ev.reader)?
    const id = card.identify()?
    print(id.name, id.kind)                        // "MIFARE Classic 1K" mifare_classic_1k

    if card.family == "mifare_classic" {
        const b = card.readBlock(4)?               // chave A de fábrica
        card.writeBlock(4, bytes("0102030405060708090a0b0c0d0e0f10", "hex"))?
    } else {
        const r = card.selectAid("A0000000031010")?
        print(r.sw, r.status, r.bytes.hex())
    }
    card.close()?
    ctx.close()?
    return true, nil
}
main()
```

## Exemplo: informação pessoal no cartão

`examples/pessoa.fg` grava, lê e apaga um registro pessoal (nome, nascimento,
documento, telefone, e-mail) num cartão de memória sem contato. O formato e a
leitura/gravação ficam em `examples/registro.fg`, que serve como módulo para
outros programas; `examples/registro.test.fg` testa tudo com cartões simulados
(`fogu test examples`), sem leitor.

```sh
fogu run examples/pessoa.fg ler
fogu run examples/pessoa.fg gravar                 # pergunta os campos no terminal
fogu run examples/pessoa.fg gravar "Ana Silva" 1990-05-12 12345678 912345678 ana@exemplo.pt
fogu run examples/pessoa.fg apagar
fogu run examples/pessoa.fg gravar --help          # --chave, --bytes, --leitor
```

```fogu
import scard from "./scard.fg"
import registro from "./examples/registro.fg"

const card = scard.connect()?                      // primeiro leitor com cartão
const area = registro.abrir(card)?                 // { key: "A0A1A2A3A4A5" } para outra chave A
area.gravar({ nome: "Ana Silva", nascimento: "1990-05-12", documento: "12345678" })?
const reg = area.ler()?                            // map com os CAMPOS
print(reg.nome, area.capacidade(), "bytes livres")
area.apagar()?
```

| cartão | onde fica | área |
|---|---|---|
| MIFARE Classic Mini / 1K / 4K | blocos de dados do setor 1 em diante (bloco 0 e trailers nunca são tocados) | 188 / 716 / 3404 bytes |
| Ultralight | páginas 4..15 | 44 bytes |
| NTAG213 / 215 / 216 | páginas a partir da 4; o tamanho vem do capability container (página 3), que anuncia 144 / 496 / 872 bytes | 140 / 492 / 868 bytes |
| cartões com chip (EMV, e-CPF, PIV...) | não há área livre padrão: `abrir()` devolve erro; use APDUs da aplicação | — |

No cartão: `"FP"` + tamanho (2 bytes) + campos em UTF-8 separados por `\n`, com o
resto da área em zeros. `--bytes 144` força a área de uma NTAG sem capability
container (sem ele a lib assume 48 bytes, o seguro, para nunca gravar nas páginas
de configuração/senha). Depois de gravar, o exemplo lê de volta e confere campo a campo.

O mesmo registro funciona num leitor sem PC/SC: o `smartusb/examples/cartao.fg` grava e lê
este formato pelo leitor NFC wCopy Smart Reader (veja `smartusb/wcopy.fg`).

## Reconhecimento do modelo

`scard.identifyAtr(atr)` (sem leitor) e `card.identify(probe = true)` devolvem:

| campo | |
|---|---|
| `name` | nome legível: `"MIFARE Classic 4K"`, `"Cartão de pagamento EMV (VISA DEBIT)"`... |
| `kind` | tipo: `mifare_classic_1k`, `mifare_ultralight`, `desfire`, `felica`, `emv`, `piv`, `openpgp`, `javacard`, `token`, `iso14443_4`, `iso7816`... |
| `family` | que operações usar: `mifare_classic`, `mifare_ultralight`, `storage`, `iso7816`, `unknown` |
| `interface` | `contact` ou `contactless` |
| `confidence` / `source` | de onde veio o nome (abaixo) |
| `matches` | todas as descrições da base do pcsc-tools para esse ATR |
| `uid`, `applications`, `storage`, `historical_text` | quando disponíveis |

Fontes, da que tem mais precedência para a que tem menos:

1. **`user`**: sua base JSON (`scard.loadAtrList("cards.json")`), para crachás e cartões da
   empresa: `[{ "atr": "3B 8F 80 01 ..", "name": "...", "kind": "..." }]`.
2. **`pcsc`**: ATR sintético dos leitores sem contato (PC/SC parte 3). Traz o padrão
   (ISO 14443 A/B, 15693, FeliCa) e o modelo (MIFARE Classic 1K/4K/Mini, Ultralight/NTAG,
   Ultralight C, Plus SL1/SL2, Jewel, Topaz, ICODE SLI).
3. **`builtin`**: ATRs conhecidos fora do padrão (DESFire).
4. **`list`**: o `smartcard_list.txt` do [pcsc-tools](https://pcsc-tools.apdu.fr/) (tokens
   e-CPF/e-CNPJ, cartões bancários, documentos de identidade, SIMs...). `fogu run atrlist`
   baixa; carregue com `scard.loadAtrList("data/smartcard_list.txt")`. Ele é GPL-2.0 e por
   isso não vai embutido na lib.
5. **`heuristic`**: nome nos bytes históricos (`JCOP`, `Yubikey`, `eToken`...) ou genérico
   (`Cartão com chip ISO 7816 (T=1)`).
6. **`probe`** (só em `card.identify()`): para cartões com chip, faz SELECT das aplicações
   conhecidas (EMV PSE/PPSE, PIV, OpenPGP, FIDO U2F, PKCS#15, NFC Type 4, GlobalPlatform)
   e lê os rótulos das aplicações EMV. Sem contato, lê também o UID. Só envia comandos de
   leitura. Passa a dar o nome quando o ATR não disse nada específico.

Nas bases, o ATR é uma regex sobre o hex maiúsculo separado por espaço, como no
pcsc-tools: `..` casa com qualquer byte.

`scard.parseAtr(atr)` decodifica o ATR em si: convenção, protocolos, Fi/Di, frequência
máxima, IFSC/BWI/CWI do T=1, classes de tensão, bytes de interface, bytes históricos
(COMPACT-TLV, inclusive se o cartão aceita APDUs estendidos) e o TCK.

## API Fogu

### Módulo

| função | |
|---|---|
| `open()` | `Context` |
| `readers()` / `connect(reader, options)` / `waitForCard(reader, timeout)` | atalhos num contexto compartilhado |
| `parseAtr(atr)` / `identifyAtr(atr)` | ATR em hex, buffer ou lista |
| `loadAtrList(path)` / `clearAtrList()` / `atrListSize()` | bases de ATRs |
| `hex(v)` / `fromHex(s)` | conversões (str, buffer, lista) |
| `version()` / `load(path)` | |

### `Context`

| método | |
|---|---|
| `readers()` | `[{ name, card, atr, state, card_name }]`; `[]` sem leitores |
| `wait(timeout = -1)` | eventos `[{ event, reader, atr, name, kind }]`: `inserted`, `removed`, `reader_added`, `reader_removed`; `[]` se o tempo acabar. `timeout` é duração (`5s`) ou ms; `-1` espera para sempre |
| `waitForCard(reader = "", timeout = -1)` | evento `inserted` (ou o cartão já presente); `nil` se o tempo acabar |
| `connect(reader = "", options = {})` | `Card`. `reader` vazio = primeiro leitor com cartão. `options`: `share` (`shared`, `exclusive`, `direct`), `protocol` (`any`, `t0`, `t1`, `raw`) |
| `close()` | |

Na primeira chamada de `wait`, leitores e cartões já presentes aparecem como
`reader_added`/`inserted`. Leitores plugados depois também são vistos. No Windows o
serviço de smart card só roda com um leitor conectado; sem ele `readers()` dá `[]` e
`wait()` fica esperando o leitor aparecer.

### `Card`

Campos: `reader`, `atr`, `protocol` (`"T0"`/`"T1"`), `kind`, `family`.

**APDUs** (respostas: `{ data, sw, sw1, sw2, ok, status, bytes }`, `status` em português):

| método | |
|---|---|
| `transmit(apdu, raw = false)` | APDU em hex, buffer ou lista. Trata `61xx` (GET RESPONSE) e `6Cxx` (Le errado) sozinho, a menos que `raw` |
| `send({ cla, ins, p1, p2 \| p1p2, data, le })` | monta o APDU (curto ou estendido conforme os tamanhos) |
| `batch(cmds, stopOnError = false)` | vários APDUs numa única transação |
| `selectAid(aid)` / `selectFile(fid)` | SELECT por nome / por FID |
| `readBinary(offset, length)` / `updateBinary(offset, data)` | |
| `readRecord(record, sfi = 0)` / `getData(tag)` | |
| `verify(pin, ref = 128)` | PIN em texto; em `63Cx` o `status` diz as tentativas restantes |
| `control(code, data)` | comando para o leitor (SCardControl), ex. `3500` = escape ACS |
| `attributes()` | fabricante, modelo e serial do leitor |

**Cartões de memória sem contato** (PC/SC parte 3; `key` em hex/buffer, `""` = `FFFFFFFFFFFF`):

| método | |
|---|---|
| `uid()` | hex |
| `readBlock(block, key, keyB)` / `writeBlock(block, data, key, keyB, unsafe)` | MIFARE Classic, 16 bytes |
| `readSector(sector, key, keyB)` / `dump(key, keyB)` | setor (lista de buffers) / cartão inteiro |
| `auth(block, key, keyB)` + `read(addr, length)` / `write(addr, data, unsafe)` | passo a passo |
| `readPages(page, count)` / `writePages(page, data, unsafe)` | Ultralight/NTAG, páginas de 4 bytes |

**Proteções de gravação.** Sem `unsafe = true`, a lib recusa gravar o bloco 0 do Classic
(UID/fabricante), os trailers (chaves e bits de acesso) e as páginas 0..3 do Ultralight
(UID, lock, OTP: irreversíveis). Mesmo com `unsafe`, um trailer com bits de acesso
inconsistentes é recusado, porque travaria o setor para sempre.

**Conexão:** `status()`, `identify(probe = true)`, `reconnect(reset = false)`,
`close(disposition = "leave")` (`leave`, `reset`, `unpower`, `eject`).

## Compatibilidade

- **Cartões T=0**: `61xx` e `6Cxx` são tratados na lib, então o mesmo código serve para
  cartões T=0 e T=1.
- **APDUs estendidos** (até 64 KB) quando `data` passa de 255 bytes ou `le` de 256.
- **MIFARE em leitores diferentes**: o load key tenta memória volátil (ACS e a maioria) e
  depois a não volátil (Omnikey); a autenticação usa `FF 86` e, em leitores antigos, `FF 88`.
- **Transações**: cada comando (e cada `batch`, `readSector`...) roda numa transação
  PC/SC, para outro programa não intercalar APDUs. Se outro programa resetar o cartão, a
  lib reconecta e repete uma vez.
- **Serviço reiniciado** (Windows remove o serviço junto com o último leitor): o contexto
  é reaberto sozinho.
- **Códigos de controle**: `control(3500, ...)` aplica a codificação de cada plataforma
  (`SCARD_CTL_CODE` no Windows, `0x42000000 + n` no pcsc-lite).

## API C (para usar de outras linguagens)

Handles são `i64`. Funções de status retornam `0`/`-1` (mensagem em `fsc_last_error`).
Respostas (JSON ou hex) vão para um buffer do chamador, terminadas em NUL; o retorno é o
tamanho escrito, `-(tamanho necessário)` se o buffer for pequeno, ou `-1` em erro. Quando o
buffer é pequeno a saída fica guardada: chame `fsc_pending` com um buffer maior. Assim
nenhum comando (uma gravação, por exemplo) é repetido por falta de buffer. Com um
callback registrado em `fsc_set_sink(sink)` (`int32_t (*sink)(const uint8_t*, size_t)`),
passar `buf = NULL, cap = 0` entrega a saída inteira pelo callback (é o que o `scard.fg` usa).

```c
int64_t fsc_version(char *buf, int64_t cap);
int64_t fsc_last_error(char *buf, int64_t cap);
int64_t fsc_pending(char *buf, int64_t cap);
int64_t fsc_open(void);                                             // contexto
int32_t fsc_close(int64_t ctx);
int64_t fsc_readers(int64_t ctx, char *buf, int64_t cap);
int64_t fsc_wait(int64_t ctx, int64_t timeout_ms, char *buf, int64_t cap);
int64_t fsc_connect(int64_t ctx, const char *reader, const char *opts_json);   // cartão
int32_t fsc_disconnect(int64_t card, int32_t disposition);          // 0 leave 1 reset 2 unpower 3 eject
int32_t fsc_reconnect(int64_t card, int32_t init);
int64_t fsc_card_status(int64_t card, char *buf, int64_t cap);
int64_t fsc_attributes(int64_t card, char *buf, int64_t cap);
int64_t fsc_transmit(int64_t card, const char *apdu_hex, int32_t flags, char *buf, int64_t cap);  // flags 1 = raw
int64_t fsc_apdu(int64_t card, const char *apdu_json, int32_t flags, char *buf, int64_t cap);
int64_t fsc_transmit_batch(int64_t card, const char *list_json, int32_t flags, char *buf, int64_t cap); // 2 = stop on error
int64_t fsc_control(int64_t card, int64_t code, const char *data_hex, char *buf, int64_t cap);
int64_t fsc_parse_atr(const char *atr_hex, char *buf, int64_t cap);
int64_t fsc_identify_atr(const char *atr_hex, char *buf, int64_t cap);
int64_t fsc_identify(int64_t card, int32_t flags, char *buf, int64_t cap);          // flags 1 = probe
int64_t fsc_db_load(const char *path);                              // .json ou smartcard_list.txt
int32_t fsc_db_clear(void);
int64_t fsc_db_count(void);
int64_t fsc_uid(int64_t card, char *buf, int64_t cap);
int32_t fsc_mifare_auth(int64_t card, int64_t block, const char *key_hex, int32_t key_type); // 0 A, 1 B
int64_t fsc_read(int64_t card, int64_t addr, int64_t len, char *buf, int64_t cap);
int32_t fsc_write(int64_t card, int64_t addr, const char *data_hex, int32_t flags);          // 1 = unsafe
int64_t fsc_mifare_read(int64_t card, int64_t block, const char *key_hex, int32_t key_type, char *buf, int64_t cap);
int64_t fsc_mifare_read_sector(int64_t card, int64_t sector, const char *key_hex, int32_t key_type, char *buf, int64_t cap);
int32_t fsc_mifare_write(int64_t card, int64_t block, const char *data_hex, const char *key_hex, int32_t key_type, int32_t flags);
```

## Limitações

- MIFARE DESFire, MIFARE Plus SL3 e FeliCa são reconhecidos, mas leitura e gravação neles
  é por APDUs (`transmit`/`send`): a autenticação deles é criptográfica e específica de
  cada aplicação.
- O PC/SC reporta NTAG21x como "Ultralight"; distinguir os dois exige comandos
  proprietários do leitor.
- Cartões de memória de contato (SLE4442/SLE5542, AT24C) dependem de comandos
  proprietários de cada leitor; use `control`/`transmit` com o manual do leitor.
- `wait` espera em fatias de 10 ms (as outras tarefas `fg` rodam); a latência para ver um
  cartão é de até ~15 ms no Windows (resolução do timer). `scard.setCooperative(false)`
  espera direto na lib (mais rápido, mas congela as outras tarefas).
- Os testes com cartão de verdade rodam só se houver leitor com cartão; sem isso, o
  comportamento com cartão é coberto pelos testes Rust com um cartão simulado.
