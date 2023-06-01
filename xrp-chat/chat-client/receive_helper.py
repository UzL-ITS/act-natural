from datetime import datetime
from xrpl.utils import ripple_time_to_datetime
from xrpl.models.transactions import Payment
from ecpy.formatters import decode_sig
from ecpy.curves import Curve
from ecpy.ecdh import ecdh, bytes_to_point
from hashlib import sha256

def date2str(xrpl_ts: int) -> str:
    dt_obj = ripple_time_to_datetime(xrpl_ts)
    print(datetime.strftime(dt_obj, '%d. %b %Y, %H:%M:%S'))

def has_amsg(sk_A: bytes, pk_B: bytes, tx: Payment):
    if tx.signing_pub_key[:2] == 'ED':
        vk = bytes.fromhex(tx.signing_pub_key[2:])
        curve = Curve.get_curve('Ed25519')
    else:
        vk = bytes.fromhex(tx.signing_pub_key)
        curve = Curve.get_curve('secp256k1')
    GG = curve.generator
    nn = curve.order
    rr, _ = decode_sig(bytes.fromhex(tx.txn_signature))
    k_chat = sha256(ecdh(curve, sk_A, pk_B) + vk).digest()
    XY = int.from_bytes(k_chat, 'big') * GG
    if XY.x % nn == rr:
        return vk, k_chat, curve
    return b'\x00', b'\x00', curve

def recover_sk(curve: Curve, k_chat: bytes, vk: bytes, tx: Payment):
    from xrpl_helper import get_signed_tx_hash
    GG = curve.generator
    nn = curve.order
    hh = int.from_bytes(get_signed_tx_hash(tx), 'big')
    rr, ss = decode_sig(bytes.fromhex(tx.txn_signature))
    sk = ((  ss  * int.from_bytes(k_chat, 'big') - hh) * pow(rr, -1, nn)) % nn
    if sk * GG == bytes_to_point(curve, vk):
        return sk
    sk = (((-ss) * int.from_bytes(k_chat, 'big') - hh) * pow(rr, -1, nn)) % nn
    if sk * GG == bytes_to_point(curve, vk):
        return sk
    return b'\x00'

def recover_msg(curve: Curve, k_chat: bytes, sk: bytes, tx: Payment):
    from xrpl_helper import get_signed_tx_hash
    from Cryptodome.Cipher import AES
    def aes_cbc_dec(ctx, key, iv):
        aes = AES.new(key, AES.MODE_CBC, iv)
        return aes.decrypt(ctx)
    nn = curve.order
    rr, ss = decode_sig(bytes.fromhex(tx.txn_signature))
    hh = get_signed_tx_hash(tx)
    iv = sha256( hh + k_chat ).digest()[:16]
    hh = int.from_bytes(hh, 'big')
    ctx_chat = ((sk * rr + hh) * pow(ss, -1, nn)) % nn
    tmp = aes_cbc_dec(ctx_chat.to_bytes(32, 'big'), k_chat, iv)
    try:
        return tx.sequence, tmp.decode('ascii')
    except UnicodeDecodeError:
        ctx_chat = ((sk * rr + hh) * pow(-ss, -1, nn)) % nn
        tmp = aes_cbc_dec(ctx_chat.to_bytes(32, 'big'), k_chat, iv)
        try:
            return tx.sequence, tmp.decode('ascii')
        except UnicodeDecodeError:
            return 0, ''
