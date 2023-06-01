from sage.all import *
from hashlib import sha256
from bitcoinlib.keys import Key
from bitcoinlib.main import logging
logging.disable(logging.ERROR)

checked_tx_ids = list()
msg_tx_ids = dict()

def receive(mailbox_addr, rcvr_sk, sndr_pk):
    rcvr_d = int(rcvr_sk, 16)
    sndr_Q = Key(sndr_pk).public_point()
    ecdh_res = ecdh(sndr_Q, rcvr_d)
    try:
        tx_ids = transactions_from_addr(mailbox_addr)
        pass
    except ConnectionError:
        print(f'[ERROR] All APIs are unreachable. Please try again later.')
        return
    tx_ids = [id for id in tx_ids if not id in checked_tx_ids]
    for tx_id in tx_ids:
        if not tx_id in msg_tx_ids:
            try:
                tx_hex = transaction_from_id(tx_id)
                pass
            except ConnectionError:
                print(f'[ERROR] All APIs are unreachable. Please try again later.')
                return
            #print(f'[>] {tx_id}')
            idx, btc_vk, k_chat = contains_amsg(tx_hex, ecdh_res)
            if idx == -1:
                checked_tx_ids.append(tx_id)
                continue
            #print(f'[>] HIT: idx: {idx}; pk: {btc_vk}')
            btc_Q = Key(btc_vk).public_point()
            hashes = transaction_hash(tx_hex, btc_vk)
            sigs = transaction_sigs(tx_hex, btc_vk)
            #print(idx, hashes)
            #print(idx, sigs)
            hh = '00'
            for i, h in hashes:
                if i == idx:
                    hh = h
            rr, ss = '00', '00'
            for i, (r,s) in sigs:
                if i == idx:
                    rr, ss = r, s
            if hh == '00' or rr == '00' or ss == '00':
                print(f'[WARN] Detected Chat message in tx {tx_id} but something is weird. Skipping.')
                continue
            btc_d, btc_sk = recover_sk(hh, rr, ss, k_chat, btc_Q)
            if btc_d == -1:
                print(f'[WARN] Recovering private key failed for tx {tx_id}. Skipping.')
                continue
            #print(f'private key recovered: {btc_sk}')
            msg = recover_msg(idx, hashes, sigs, btc_d, k_chat)
            msg_tx_ids[tx_id] = (sndr_pk, msg)
        print(f'{msg_tx_ids[tx_id][0]}: {msg_tx_ids[tx_id][1]} in tx {tx_id}')
        pass
    pass

def recover_msg(idx, hashes, sigs, sndr_d, k_chat):
    msg = ''
    for (i, hh), (j, (rr, ss)) in zip(hashes, sigs):
        if i != j:
            print('[WARN] Something is strange...')
        if i == idx:
            continue
        hh, rr, ss = int(hh, 16), int(rr, 16), int(ss, 16)
        ctxs = compute_k_from_d(hh, rr, ss, sndr_d)
        for i, ctx in enumerate(ctxs):
            iv = sha256(hh.to_bytes(32, 'big') + bytes.fromhex(k_chat)).digest()[:16]
            ptx = decrypt(int(ctx).to_bytes(32, 'big'), bytes.fromhex(k_chat), iv=iv)
            try:
                msg += ptx.decode('ascii')
                pass
            except:
                pass
            pass
        pass
    return msg

def recover_sk(hh, rr, ss, k_chat, sndr_Q):
    '''Recover Private Key'''
    hh = int(hh, 16)
    rr, ss = int(rr, 16), int(ss, 16)
    dd = compute_d_from_k(hh, rr, ss, int(k_chat, 16), sndr_Q)
    if dd == -1:
        return -1, None
    sk = int(dd).to_bytes(32, 'big').hex()
    return dd, sk

def contains_amsg(tx_hex, ecdh_res):
    '''Check whether transaction contains chat message'''
    sigs = transaction_sigs(tx_hex)
    pks = _input_pubKeys(tx_hex)
    for idx, (rr, _) in sigs:
        k_chat = sha256(ecdh_res + bytes.fromhex(pks[idx][1])).hexdigest()
        r_chat = int((int(k_chat, 16) * secp256k1.G).xy()[0]).to_bytes(32, 'big').hex()
        #print(f'idx: {idx}\tk_chat: {k_chat}\tr_chat: {r_chat}')
        if r_chat == rr:
            return idx, pks[idx][1], k_chat
        pass
    return -1, None, None


'''
    AES Helper
'''
def decrypt(ctx, key, iv=None):
    from Cryptodome.Cipher import AES
    if iv is None:
        cipher = AES.new(key, AES.MODE_ECB)
    else:
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.decrypt(ctx)


'''
    Curve SECP256k1 Helper
'''
class secp256k1:
    p = 0x0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    Fp = GF(p)
    a = 0x0000000000000000000000000000000000000000000000000000000000000000
    b = 0x0000000000000000000000000000000000000000000000000000000000000007
    # E: x^2 = x^3 + ax + b over Fp
    E = EllipticCurve(Fp, [0, 0, 0, a, b])
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    G = E(Gx, Gy)
    # n == G.order()
    n = 0x0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    Fn = GF(n)
    pass


'''
    ECDSA Attacks Helper
'''
def compute_d_from_k(message_digest, signature_r, signature_s, nonce_k, public_Q):
    QQ = secp256k1.E(public_Q[0], public_Q[1])
    hm = secp256k1.Fn(message_digest)
    rr = secp256k1.Fn(signature_r)
    ss = secp256k1.Fn(signature_s)
    kk = secp256k1.Fn(nonce_k)
    d1 = lift((ss*kk - hm) * rr**-1)
    d2 = lift(((-ss)*kk - hm) * rr**-1)
    if d1 * secp256k1.G == QQ:
        return d1
    elif d2 * secp256k1.G == QQ:
        return d2
    return -1

def compute_k_from_d(message_digest, signature_r, signature_s, secret_d):
    hm = secp256k1.Fn(message_digest)
    rr = secp256k1.Fn(signature_r)
    ss = secp256k1.Fn(signature_s)
    dd = secp256k1.Fn(secret_d)
    return lift((dd*rr + hm) * ss**-1), lift((dd*rr + hm) * (-ss)**-1)


'''
    ECDH Helper
'''
def hash(point_xy):
    import hashlib
    x_bytes = int(point_xy[0]).to_bytes(32, 'big')
    y_bytes = int(point_xy[1]).to_bytes(32, 'big')
    version = bytes([(y_bytes[31] & 0x01) | 0x02])
    return hashlib.sha256(version + x_bytes).digest()

def ecdh(pubkey, seckey):
    Qx, Qy = pubkey
    d = seckey
    Q = secp256k1.E(Qx, Qy)
    P = d*Q
    return hash(P.xy())


'''
    Transaction Helper
'''
from bit.network import NetworkAPI
from bitcoinlib.encoding import convert_der_sig
from bitcoinlib.transactions import Transaction

def transactions_from_addr(addr):
    return NetworkAPI.get_transactions_testnet(addr)

def transaction_from_id(txid):
    return NetworkAPI.get_transaction_by_id_testnet(txid)

def transaction_hash(tx_hex, pubKey):
    tx = Transaction.parse(tx_hex, network='testnet')
    idxs = _inputs_from_pubKey(tx_hex, pubKey)
    hashes = list()
    for idx in idxs:
        hashes.append((idx, tx.signature_hash(sign_id=idx, as_hex=True)))
        pass
    return hashes

def transaction_sigs(tx_hex, pk=None):
    tx = Transaction.parse(tx_hex, network='testnet')
    sigs = list()
    for idx, inp in enumerate(tx.inputs):
        sigScript = inp.unlocking_script.hex()
        if len(sigScript) == 0:
            continue
        if pk is None or pk == _parse_pubKey_from_sigScript(sigScript):
            sigs.append((idx, _parse_sig_from_sigScript(sigScript)))
        pass
    pass
    return sigs

def _parse_sig_from_sigScript(sigScript):
    sigScript_bytes = bytearray.fromhex(sigScript)
    sig_bytes = sigScript_bytes[1:sigScript_bytes[0]]
    sig_hex = convert_der_sig(sig_bytes)
    return sig_hex[:64], sig_hex[64:]

def _parse_pubKey_from_sigScript(sigScript):
    sigScript_bytes = bytearray.fromhex(sigScript)
    pk_bytes = sigScript_bytes[sigScript_bytes[0]+1:]
    return pk_bytes[1:pk_bytes[0]+1].hex()

def _inputs_from_pubKey(tx_hex, pubKey):
    idxs = list()
    for i, pk in _input_pubKeys(tx_hex):
        if pubKey == pk:
            idxs.append(i)
            pass
        pass
    return idxs

def _input_pubKeys(tx_hex):
    tx = Transaction.parse(tx_hex, network='testnet')
    pubkeys = list()
    for i, inp in enumerate(tx.inputs):
        sigScript = inp.unlocking_script.hex()
        if not len(sigScript) > 0:
            continue
        pubkeys.append((i, _parse_pubKey_from_sigScript(sigScript)))
        pass
    return pubkeys
