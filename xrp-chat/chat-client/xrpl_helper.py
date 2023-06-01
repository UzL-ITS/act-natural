from io_helper import prnt
from xrpl.wallet import Wallet
from xrpl.models.transactions import Payment
JSON_RPC_CLIENT = None

def connect(url):
    global JSON_RPC_CLIENT
    from xrpl.clients import JsonRpcClient
    JSON_RPC_CLIENT = JsonRpcClient(url)
    pass

def fund_wallet(wallet: Wallet):
    from xrpl.clients import JsonRpcClient
    from xrpl.wallet import generate_faucet_wallet
    tmp_client = JsonRpcClient("https://s.altnet.rippletest.net:51234/")
    generate_faucet_wallet(tmp_client, wallet)
    pass

def get_balance(addr):
    from xrpl.account import get_balance
    return get_balance(addr, JSON_RPC_CLIENT)

def get_addr(pk):
    from xrpl.core.keypairs import derive_classic_address
    return derive_classic_address(pk)

def get_regularkey_transactions(addr):
    from xrpl.models.transactions import SetRegularKey
    from xrpl.core.keypairs import is_valid_message
    from xrpl.account import get_account_transactions
    txs = [tx for tx in get_account_transactions(addr, JSON_RPC_CLIENT) if tx['tx']['TransactionType'] == 'SetRegularKey']
    ret = list()
    for tx in txs:
        tx_data = tx['tx']
        srk = SetRegularKey(
            account=tx_data['Account'],
            fee=tx_data['Fee'],
            flags=tx_data['Flags'],
            last_ledger_sequence=tx_data['LastLedgerSequence'],
            regular_key=tx_data['RegularKey'],
            sequence=tx_data['Sequence'],
            signing_pub_key=tx_data['SigningPubKey'],
            txn_signature=tx_data['TxnSignature'],
        )
        assert is_valid_message(get_signed_tx_data(srk), bytes.fromhex(srk.txn_signature), srk.signing_pub_key)
        ret.append(srk)
        pass
    return ret


def get_payment_transactions(addr):
    from xrpl.core.keypairs import is_valid_message
    from xrpl.account import get_account_payment_transactions
    txs = get_account_payment_transactions(addr, JSON_RPC_CLIENT)
    ret = list()
    for tx in txs:
        tx_data = tx['tx']
        p = Payment(
            account=tx_data['Account'],
            amount=tx_data['Amount'],
            destination=tx_data['Destination'],
            fee=tx_data['Fee'],
            flags=tx_data['Flags'],
            last_ledger_sequence=tx_data['LastLedgerSequence'],
            sequence=tx_data['Sequence'],
            signing_pub_key=tx_data['SigningPubKey'],
            txn_signature=tx_data['TxnSignature'],
            )
        #assert is_valid_message(get_signed_tx_data(p), bytes.fromhex(p.txn_signature), p.signing_pub_key)
        ret.append(p)
        pass
    return ret

def get_signed_tx_data(tx: Payment):
    from xrpl.core import binarycodec
    tx_enc = bytes.fromhex(binarycodec.encode_for_signing(tx.to_xrpl()))
    return tx_enc

def get_signed_tx_hash(tx: Payment):
    from xrpl.core.keypairs.helpers import sha512_first_half
    tx_enc = get_signed_tx_data(tx)
    if tx.signing_pub_key[:2] == 'ED':
        return tx_enc
    return sha512_first_half(tx_enc)

def sign_and_transmit(wallet: Wallet, tx, nonce=None):
    from xrpl.core.binarycodec.exceptions import XRPLBinaryCodecException
    from xrpl.transaction import safe_sign_transaction, send_reliable_submission, autofill
    try:
        tx_filled = autofill(tx, JSON_RPC_CLIENT)
    except XRPLBinaryCodecException as e:
        prnt(f'[!] Error: {e}')
        return
    tx_signed = safe_sign_transaction(tx_filled, wallet, JSON_RPC_CLIENT, nonce=nonce)
    tx_result = send_reliable_submission(tx_signed, JSON_RPC_CLIENT).result
    return tx_result

def set_sign_key(wallet: Wallet, new_signkey: Wallet, old_signkey: Wallet = None, nonce=None):
    from xrpl.models import XRPLModelException
    from xrpl.models.transactions import SetRegularKey
    try:
        tx = SetRegularKey(
            account=wallet.classic_address,
            regular_key=new_signkey.classic_address
        )
    except XRPLModelException as e:
        prnt(f'[!] Error: {e}')
        return
    if old_signkey:
        tx_result = sign_and_transmit(old_signkey, tx, nonce=nonce)
    else:
        tx_result = sign_and_transmit(wallet, tx) # Never leak master key!
    if tx_result['meta']['TransactionResult'] != 'tesSUCCESS':
        prnt(f"[!] Error: Sending transaction failed ({tx_result['meta']['TransactionResult']})")
        return
    prnt(f"[+] Old signing key: {old_signkey.public_key if old_signkey else '-None-'}")
    prnt(f"[+] New signing key: {new_signkey.public_key}")
    prnt(f"[+] Hash: {tx_result['hash']}")
    prnt(f"[+] Sig:  {tx_result['TxnSignature']}")
    return tx_result['hash']

def pay(wallet: Wallet, signkey: Wallet, amount, destination, nonce=None):
    from xrpl.models import XRPLModelException
    from xrpl.account import get_next_valid_seq_number
    wallet.sequence = get_next_valid_seq_number(wallet.classic_address, JSON_RPC_CLIENT)
    try:
        tx_payment = Payment(
            account=wallet.classic_address,
            amount=str(amount),
            destination=destination
        )
    except XRPLModelException as e:
        prnt(f'[!] Error: {e}')
        return
    tx_result = sign_and_transmit(signkey, tx_payment, nonce)
    if tx_result['meta']['TransactionResult'] != 'tesSUCCESS':
        prnt(f"[!] Error: Sending transaction failed ({tx_result['meta']['TransactionResult']})")
        return
    prnt(f"[+] Tx: {tx_result['Account']} -> {tx_result['Destination']} ({tx_result['Amount']} XRP)")
    prnt(f"[+] Hash: {tx_result['hash']}")
    prnt(f"[+] Sig:  {tx_result['TxnSignature']}")
    return tx_result['hash']
