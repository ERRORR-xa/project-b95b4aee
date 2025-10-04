import os
from flask import Flask, request, jsonify, redirect, url_for
import json, os, aiohttp, asyncio, requests, binascii
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import like_pb2, like_count_pb2, uid_generator_pb2
from google.protobuf.message import DecodeError

app = Flask(__name__)
ACCOUNTS_FILE = 'accounts.json'

# تحميل الحسابات من ملف JSON مع دعم كلا التنسيقين
def load_accounts():
    if not os.path.exists(ACCOUNTS_FILE):
        return {}
    
    with open(ACCOUNTS_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    accounts = {}
    
    # إذا كان التنسيق قديم (كائن)
    if isinstance(data, dict):
        accounts = data
    # إذا كان التنسيق جديد (مصفوفة)
    elif isinstance(data, list):
        for account in data:
            if isinstance(account, dict) and 'uid' in account and 'password' in account:
                accounts[account['uid']] = account['password']
    
    return accounts

# طلب تحويل التوكن الخام إلى JWT عبر API الجديد
async def fetch_token(session, uid, password):
    url = f"https://gelmi-jwt-token.vercel.app/api/get_jwt?key=gelmi30days&guest_uid={uid}&guest_password={password}"
    try:
        async with session.get(url, timeout=10) as res:
            if res.status == 200:
                text = await res.text()
                try:
                    data = json.loads(text)
                    # التعامل مع الاستجابة الجديدة التي تحتوي على مصفوفة من الكائنات
                    if isinstance(data, list) and len(data) > 0 and "token" in data[0]:
                        return data[0]["token"]
                    # حالة احتياطية إذا كانت الاستجابة كائن مباشر
                    elif isinstance(data, dict) and "token" in data:
                        return data["token"]
                except Exception as e:
                    print(f"Error parsing token response: {e}")
                    return None
    except Exception as e:
        print(f"Error fetching token: {e}")
        return None
    return None

# تحويل جميع الحسابات إلى JWTs
async def get_tokens_live():
    accounts = load_accounts()
    tokens = []
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_token(session, uid, password) for uid, password in accounts.items()]
        results = await asyncio.gather(*tasks)
        tokens = [token for token in results if token]
    return tokens

def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return binascii.hexlify(cipher.encrypt(pad(plaintext, AES.block_size))).decode()

def create_uid_proto(uid):
    pb = uid_generator_pb2.uid_generator()
    pb.saturn_ = int(uid)
    pb.garena = 1
    return pb.SerializeToString()

def create_like_proto(uid):
    pb = like_pb2.like()
    pb.uid = int(uid)
    return pb.SerializeToString()

def decode_protobuf(binary):
    try:
        pb = like_count_pb2.Info()
        pb.ParseFromString(binary)
        return pb
    except DecodeError:
        return None

def make_request(enc_uid, token):
    url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB50"
    }
    try:
        res = requests.post(url, data=bytes.fromhex(enc_uid), headers=headers, verify=False)
        return decode_protobuf(res.content)
    except:
        return None

async def send_request(enc_uid, token):
    url = "https://clientbp.ggblueshark.com/LikeProfile"
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB50"
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=bytes.fromhex(enc_uid), headers=headers) as r:
                return r.status
    except:
        return None

async def send_likes(uid, tokens):
    enc_uid = encrypt_message(create_like_proto(uid))
    tasks = [send_request(enc_uid, token) for token in tokens]
    return await asyncio.gather(*tasks)

@app.route('/like', methods=['GET'])
def like_handler():
    uid = request.args.get("uid")
    if not uid:
        return jsonify({"error": "Missing UID"}), 400

    tokens = asyncio.run(get_tokens_live())
    if not tokens:
        return jsonify({"error": "No valid tokens available"}), 401

    enc_uid = encrypt_message(create_uid_proto(uid))
    before = make_request(enc_uid, tokens[0])
    if not before:
        return jsonify({"error": "Failed to retrieve player info"}), 500

    before_data = json.loads(MessageToJson(before))
    likes_before = int(before_data.get("AccountInfo", {}).get("Likes", 0))
    nickname = before_data.get("AccountInfo", {}).get("PlayerNickname", "Unknown")

    responses = asyncio.run(send_likes(uid, tokens))
    success_count = sum(1 for r in responses if r == 200)

    after = make_request(enc_uid, tokens[0])
    likes_after = 0
    if after:
        after_data = json.loads(MessageToJson(after))
        likes_after = int(after_data.get("AccountInfo", {}).get("Likes", 0))

    return jsonify({
        "PlayerNickname": nickname,
        "UID": uid,
        "LikesBefore": likes_before,
        "LikesAfter": likes_after,
        "LikesGivenByAPI": likes_after - likes_before,
        "SuccessfulRequests": success_count,
        "status": 1 if likes_after > likes_before else 2
    })

@app.route('/<uid>', methods=['GET'])
def handle_uid(uid):
    return redirect(url_for('like_handler', uid=uid))

@app.route('/')
def home():
    return jsonify({"status": "online", "message": "Like API is running ✅"})

if __name__ == '__main__':
    if __name__ == '__main__':
    app.run()
