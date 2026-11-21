import os
import sys
import ssl
import json
import time
import random
import socket
import struct
import hashlib

try:
    from ecdsa import SigningKey, SECP256k1
except ImportError:
    print("Нет библиотеки ecdsa. Установите:  pip install ecdsa")
    sys.exit(1)

# --------------------------- НАСТРОЙКИ ---------------------------
SERVERS = [                       # публичные Electrum-серверы (SSL, порт 50002)
    ("electrum.blockstream.info", 50002),
    ("electrum.emzy.de", 50002),
    ("electrum.bitaroo.net", 50002),
    ("fulcrum.sethforprivacy.com", 50002),
]
USE_SSL    = True                 # False — если используете порты 50001
TIMEOUT    = 20                   # таймаут ответа сервера, сек
FOUND_FILE = "found_wallets.csv"  # куда сохранять найденное
LOG_EVERY  = 50                  # прогресс каждые N ключей
# ------------------------------------------------------------------

# ===================== ХЭШИ =====================

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def _ripemd160_pure(msg: bytes) -> bytes:
    """RIPEMD-160 на чистом Python (запасной вариант, если в OpenSSL его нет)."""
    K  = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    Kp = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
    R  = [[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
          [7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8],
          [3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12],
          [1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2],
          [4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]]
    Rp = [[5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12],
          [6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2],
          [15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13],
          [8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14],
          [12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]]
    S  = [[11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8],
          [7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12],
          [11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5],
          [11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12],
          [9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]]
    Sp = [[8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6],
          [9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11],
          [9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5],
          [15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8],
          [8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]]

    def f(j, x, y, z):
        if j < 16: return (x ^ y ^ z) & 0xFFFFFFFF
        if j < 32: return ((x & y) | (~x & z)) & 0xFFFFFFFF
        if j < 48: return ((x | ~y) ^ z) & 0xFFFFFFFF
        if j < 64: return ((x & z) | (y & ~z)) & 0xFFFFFFFF
        return (x ^ (y | ~z)) & 0xFFFFFFFF

    data = bytearray(msg)
    bitlen = len(msg) * 8
    data.append(0x80)
    while len(data) % 64 != 56:
        data.append(0)
    data += struct.pack("<Q", bitlen)

    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    for off in range(0, len(data), 64):
        X = struct.unpack("<16I", bytes(data[off:off + 64]))
        A, B, C, D, E = h
        Ap, Bp, Cp, Dp, Ep = h
        for j in range(80):
            q, p = j // 16, j % 16
            T = (A + f(j, B, C, D) + X[R[q][p]] + K[q]) & 0xFFFFFFFF
            T = (_rol(T, S[q][p]) + E) & 0xFFFFFFFF
            A, E, D, C, B = E, D, _rol(C, 10), B, T
            T = (Ap + f(79 - j, Bp, Cp, Dp) + X[Rp[q][p]] + Kp[q]) & 0xFFFFFFFF
            T = (_rol(T, Sp[q][p]) + Ep) & 0xFFFFFFFF
            Ap, Ep, Dp, Cp, Bp = Ep, Dp, _rol(Cp, 10), Bp, T
        T   = (h[1] + C + Dp) & 0xFFFFFFFF
        h[1] = (h[2] + D + Ep) & 0xFFFFFFFF
        h[2] = (h[3] + E + Ap) & 0xFFFFFFFF
        h[3] = (h[4] + A + Bp) & 0xFFFFFFFF
        h[4] = (h[0] + B + Cp) & 0xFFFFFFFF
        h[0] = T
    return struct.pack("<5I", *h)

def ripemd160(b: bytes) -> bytes:
    try:
        h = hashlib.new("ripemd160")
        h.update(b)
        return h.digest()
    except Exception:
        return _ripemd160_pure(b)

def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))

# ===================== КОДИРОВАНИЕ АДРЕСОВ =====================

B58    = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def base58_encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + out

def _checksum(payload: bytes) -> bytes:
    return sha256(sha256(payload))[:4]

def base58check(version: int, payload: bytes) -> str:
    data = bytes([version]) + payload
    return base58_encode(data + _checksum(data))

def wif_encode(priv: bytes, compressed: bool) -> str:
    payload = b"\x80" + priv + (b"\x01" if compressed else b"")
    return base58_encode(payload + _checksum(payload))

def _bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= gen[i]
    return chk

def _convertbits(data, frm, to):
    acc = bits = 0
    ret = []
    maxv = (1 << to) - 1
    for b in data:
        acc = (acc << frm) | b
        bits += frm
        while bits >= to:
            bits -= to
            ret.append((acc >> bits) & maxv)
    if bits:
        ret.append((acc << (to - bits)) & maxv)
    return ret

def bech32_p2wpkh(h160: bytes) -> str:
    data = [0] + _convertbits(h160, 8, 5)
    hrp = [ord(c) >> 5 for c in "bc"] + [0] + [ord(c) & 31 for c in "bc"]
    pm = _bech32_polymod(hrp + data + [0] * 6) ^ 1
    chk = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return "bc1" + "".join(BECH32[d] for d in data + chk)

# ===================== ГЕНЕРАЦИЯ КЛЮЧЕЙ И АДРЕСОВ =====================

def random_private_key() -> bytes:
    while True:
        priv = os.urandom(32)
        if 0 < int.from_bytes(priv, "big") < SECP256k1.order:
            return priv

def derive_entries(priv: bytes):
    """[(адрес, WIF, scriptPubKey, тип), ...] для одного приватного ключа."""
    sk = SigningKey.from_string(priv, curve=SECP256k1)
    pub = sk.get_verifying_key().to_string()          # 64 байта: X || Y
    x, y = pub[:32], pub[32:]
    pub_c = (b"\x03" if y[-1] & 1 else b"\x02") + x    # сжатый pubkey
    pub_u = b"\x04" + pub                             # несжатый pubkey

    h160_c = hash160(pub_c)
    h160_u = hash160(pub_u)
    wif_c = wif_encode(priv, True)
    wif_u = wif_encode(priv, False)

    entries = []
    # 1) Legacy P2PKH, сжатый ключ (адрес на "1...")
    entries.append((base58check(0x00, h160_c), wif_c,
                    b"\x76\xa9\x14" + h160_c + b"\x88\xac", "P2PKH-compressed"))
    # 2) Legacy P2PKH, несжатый ключ (старые кошельки 2010–2013 гг.)
    entries.append((base58check(0x00, h160_u), wif_u,
                    b"\x76\xa9\x14" + h160_u + b"\x88\xac", "P2PKH-uncompressed"))
    # 3) P2SH-P2WPKH (адрес на "3...")
    redeem = b"\x00\x14" + h160_c
    h160_r = hash160(redeem)
    entries.append((base58check(0x05, h160_r), wif_c,
                    b"\xa9\x14" + h160_r + b"\x87", "P2SH-P2WPKH"))
    # 4) Native SegWit P2WPKH (адрес на "bc1...")
    entries.append((bech32_p2wpkh(h160_c), wif_c,
                    b"\x00\x14" + h160_c, "P2WPKH"))
    return entries

def scripthash_of(script: bytes) -> str:
    """Electrum-скриптхэш: sha256(script), байты в обратном порядке, hex."""
    return sha256(script)[::-1].hex()

def self_test():
    priv = bytes(31) + b"\x01"      # приватный ключ = 1, известные векторы
    d = {kind: (a, w) for a, w, _s, kind in derive_entries(priv)}
    checks = [
        (d["P2PKH-compressed"][0],   "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
        (d["P2PKH-uncompressed"][0], "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"),
        (d["P2WPKH"][0],              "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
        (d["P2PKH-compressed"][1],    "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"),
    ]
    for got, want in checks:
        if got != want:
            sys.exit(f"Самопроверка провалена: {got} != {want}")
    print("[i] Самопроверка генерации ключей/адресов: OK")

# ===================== КЛИЕНТ ELECTRUM =====================

class Electrum:
    def __init__(self, servers, use_ssl=True, timeout=20):
        self.servers, self.use_ssl, self.timeout = list(servers), use_ssl, timeout
        self.sock, self.buf, self._id = None, b"", 0
        self.connect()

    def connect(self):
        servers = self.servers[:]
        random.shuffle(servers)
        last = None
        for host, port in servers:
            sock = None
            try:
                sock = socket.create_connection((host, port), timeout=self.timeout)
                if self.use_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)
                self.sock, self.buf, self._id = sock, b"", 0
                self._request("server.version", ["mozg-balance-checker", "1.4"])
                print(f"[i] Подключено к Electrum-серверу: {host}:{port}")
                return
            except Exception as e:
                last = e
                if sock:
                    try: sock.close()
                    except Exception: pass
        raise ConnectionError(f"Не удалось подключиться к серверам: {last}")

    def _request(self, method, params):
        self._id += 1
        rid = self._id
        msg = json.dumps({"jsonrpc": "2.0", "id": rid,
                          "method": method, "params": params})
        self.sock.settimeout(self.timeout)
        self.sock.sendall((msg + "\n").encode())
        while True:
            while b"\n" not in self.buf:
                chunk = self.sock.recv(65536)
                if not chunk:
                    raise ConnectionError("сервер закрыл соединение")
                self.buf += chunk
            line, self.buf = self.buf.split(b"\n", 1)
            try:
                resp = json.loads(line)
            except ValueError:
                continue
            if resp.get("id") == rid:
                if resp.get("error"):
                    raise RuntimeError(f"ошибка сервера: {resp['error']}")
                return resp.get("result")

    def get_balance(self, scripthash):
        """Возвращает (confirmed, unconfirmed) в сатоши."""
        last = None
        for _ in range(3):
            try:
                res = self._request("blockchain.scripthash.get_balance", [scripthash])
                return int(res.get("confirmed", 0)), int(res.get("unconfirmed", 0))
            except Exception as e:
                last = e
                try:
                    self.connect()
                except Exception:
                    time.sleep(2)
        raise ConnectionError(f"баланс не получен: {last}")

# ===================== ОСНОВНОЙ ЦИКЛ =====================

def save_found(addr, wif, kind, conf, unconf):
    new = not os.path.exists(FOUND_FILE)
    with open(FOUND_FILE, "a", encoding="utf-8", newline="") as f:
        if new:
            f.write("time,address,type,wif,confirmed_sat,unconfirmed_sat\n")
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')},{addr},{kind},{wif},{conf},{unconf}\n")

def main():
    self_test()
    ec = Electrum(SERVERS, USE_SSL, TIMEOUT)
    total = found = 0
    t0 = time.time()
    print(f"[i] Генерация запущена. Остановка — Ctrl+C.")
    print(f"[i] Найденное сохраняется в: {os.path.abspath(FOUND_FILE)}")
    try:
        while True:
            priv = random_private_key()
            for addr, wif, script, kind in derive_entries(priv):
                try:
                    conf, unconf = ec.get_balance(scripthash_of(script))
                except Exception as e:
                    print(f"[!] {e}")
                    break
                if conf or unconf:
                    found += 1
                    save_found(addr, wif, kind, conf, unconf)
                    print("=" * 64)
                    print("*** НАЙДЕН БАЛАНС ***")
                    print(f"Адрес:  {addr}  ({kind})")
                    print(f"WIF:    {wif}")
                    print(f"Баланс: {conf} подтв. + {unconf} неподтв. (сатоши)")
                    print("=" * 64, flush=True)
            total += 1
            if total % LOG_EVERY == 0:
                dt = time.time() - t0
                print(f"[{time.strftime('%H:%M:%S')}] ключей: {total} | "
                      f"найдено: {found} | скорость: {total / dt:.1f} кл/с", flush=True)
    except KeyboardInterrupt:
        print(f"\nОстановлено. Проверено ключей: {total}, с балансом: {found}.")

if __name__ == "__main__":
    main()
