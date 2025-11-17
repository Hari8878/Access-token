# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify
import requests, json, base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from google.protobuf.internal.encoder import _VarintBytes
app = Flask(__name__)
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV  = b'6oyZDr22E3ychjM%'
# ---------- AES ----------
def aes_dec(data):
    if len(data) % 16 == 0:
        d = AES.new(AES_KEY, AES.MODE_CBC, AES_IV).decrypt(data)
        try:
            return unpad(d, AES.block_size)
        except:
            return d
    return data

def aes_enc(data):
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(data, AES.block_size))
# ---------- Proto helpers ----------
def decode_varint(d, i):
    shift = 0; result = 0
    while True:
        b = d[i]; i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80): return result, i
        shift += 7
def parse_protobuf(d):
    i = 0; result = {}
    while i < len(d):
        key, i = decode_varint(d, i)
        f, wt = key >> 3, key & 7
        if wt == 0:
            val, i = decode_varint(d, i)
        elif wt == 2:
            l, i = decode_varint(d, i)
            val = d[i:i+l]; i += l
            try:
                val = val.decode()
            except:
                val = val.hex()
        else:
            break
        result[f] = val
    return result
def encode_varint(n):
    o = []
    while True:
        b = n & 0x7F; n >>= 7
        if n:
            o.append(b | 0x80)
        else:
            o.append(b)
            break
    return bytes(o)
def encode_kv(f, wt, v): return _VarintBytes((f << 3) | wt) + v
def encode_int32(f, n): return encode_kv(f, 0, encode_varint(n))
def encode_string(f, s):
    b = s.encode()
    return encode_kv(f, 2, encode_varint(len(b)) + b)

def create_proto(flds):
    p = b""
    for k, v in flds.items():
        if isinstance(v, int):
            p += encode_int32(k, v)
        elif isinstance(v, str):
            p += encode_string(k, v)
        else:
            p += encode_kv(k, 2, encode_varint(len(v)) + v)
    return p
def get_latest_version():
    try:
        url = "https://version.ggwhitehawk.com/live/ver.php?device=android"
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; Redmi Note 8 Pro Build/RP1A.200720.011)"
        }
        resp = requests.get(url, headers=headers, timeout=5)
        data = resp.json()
        latest = data.get("latest_release_version", "")  # fallback to OB51
      #  print(f"🆕 Latest Release Version: {latest}")
        return latest
    except Exception as e:
        #print(f"⚠️ Failed to get version: {e}")
        return "OB Failed "
# ==========================================================
# ===============      /fetch ROUTE      ====================
# ==========================================================
@app.route('/fetch', methods=['GET'])
def fetch():
    token = request.args.get("token")
    latest_version = get_latest_version()
    if not token:
        return jsonify({"error": "Missing token"}), 400
    try:
        # Step 1: Extract from Garena callback
        url = f"https://api-otrss.garena.com/support/callback/?access_token={token}"
        html = requests.get(url, timeout=5).text
        pos = html.find('"searchParams\\":')
        if pos == -1:
            return jsonify({"error": "'searchParams' not found"}), 404
        snippet = html[pos:pos + 600]
        start, end = snippet.find("{"), snippet.find("}", snippet.find("{"))
        if start == -1 or end == -1:
            return jsonify({"error": "JSON braces not found"}), 404
        frag = snippet[start:end + 1].replace('\\"', '"').replace('\\u0026', '&')
        data = json.loads(frag)
        actk = data.get('access_token', '?')
        acc_id = data.get('account_id', '?')
        nickname = data.get('nickname', '?')
        # Step 2: Inspect token
        inspect_url = f"https://ffmconnect.live.gop.garenanow.com/oauth/token/inspect?token={actk}"
        headers = {
            'User-Agent': "GarenaMSDK/4.0.19P10(Redmi Note 8 Pro ;Android 11;en;IN;)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip"
        }
        resp = requests.get(inspect_url, headers=headers, timeout=5)
        data2 = resp.json()
        platform = data2.get('platform', '?')
        open_id = data2.get('open_id', '?')
        # Step 3: Create MajorLogin payload
        payloadd = create_proto({
            22: open_id,
            29: actk,
            99: str(platform),
            100: str(platform)
        })
        enc = aes_enc(payloadd)
        # Step 4: MajorLogin request
        headers2 = {
            'User-Agent': "Dalvik/2.1.0",
            'Content-Type': "application/octet-stream",
            'X-GA': "v1 1",
            'ReleaseVersion': latest_version
        }
        resp2 = requests.post(
            "https://loginbp.ggblueshark.com/MajorLogin",
            data=enc,
            headers=headers2,
            timeout=6
        )
        if resp2.status_code != 200:
            return jsonify({"error": "MajorLogin failed"}), 500
        decoded = parse_protobuf(resp2.content)
        tokeningame = decoded.get(8, None)
        return jsonify({
            "Platform_Type": platform or "N/A",
            "Open_id": open_id or "N/A",
            "Access": actk or "N/A",                             
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
# ---------- Run ----------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
