from xrpl.core.keypairs import ChatNonce
from receive_helper import *
from io_helper import prnt, inp
from xrpl_helper import connect, fund_wallet, get_balance, set_sign_key, pay, get_payment_transactions, get_regularkey_transactions

from collections import namedtuple
ChatKey = namedtuple('ChatKey', ['sk', 'pk', 'seed'])
ChatMsg = namedtuple('ChatMsg', ['msg', 'rcv'])
Contact = namedtuple('Contact', ['addr', 'pk_chat'])

contacts = dict()
chats = dict()

def print_info(private=False):
    global WALLET, SIGNKEY, CHATKEY
    prnt(f'Chat public key:            {CHATKEY.pk.hex().upper()}')
    prnt(f'Chat private key:           {CHATKEY.sk.hex().upper() if private else "-HIDDEN-"}')
    if private:
        prnt(f'Chat seed:                  {CHATKEY.seed}')
    prnt(f'Wallet public master key:   {WALLET.public_key}')
    prnt(f'Wallet private master key:  {WALLET.private_key if private else "-HIDDEN-"}')
    if private:
        prnt(f'Wallet seed:                {WALLET.seed}')
    prnt(f'Wallet public sign key:     {SIGNKEY.public_key}')
    prnt(f'Wallet private sign key:    {SIGNKEY.private_key if private else "-HIDDEN-"}')
    prnt(f'Wallet address:             {WALLET.classic_address}')

def print_contact_names():
    global contacts
    prnt(f'[+] Contacts:')
    for c in sorted(contacts.keys()):
        prnt(f'[+]   - {c}')
        pass
    pass

def show_contact():
    global contacts
    print_contact_names()
    prnt('Contact name for more details [none]: ', end='')
    name = inp()
    if name == '':
        return
    if not name in contacts:
        prnt('[!] Contact is not in the list of contacts. Did you misspell the name?')
        return
    prnt(f'[+] Details for {name}:')
    prnt(f'[+]   Wallet address:  {contacts[name].addr}')
    prnt(f'[+]   Public chat key: {contacts[name].pk_chat.hex()}')
    pass

def update_contact(name, update_addr=False, update_pk_chat=False):
    global contacts
    if update_addr:
        prnt('Contact wallet address: ', end='')
        addr = inp()
        if addr == '':
            addr = None
    else:
        addr = contacts[name].addr
    if update_pk_chat:
        prnt('Contact public chat key: ', end='')
        try:
            pk_chat = inp()
            if pk_chat == '':
                pk_chat = None
            else:
                pk_chat = bytes.fromhex(pk_chat)
        except ValueError as e:
            prnt(f'[!] Error: {e}')
            return
    else:
        pk_chat = contacts[name].pk_chat
    contacts[name] = Contact(addr, pk_chat)
    prnt(f'[+] Updated contact {name}.')
    pass

def add_contact():
    global contacts
    prnt('Contact name: ', end='')
    name = inp()
    if name in contacts:
        prnt(f'[+] Contact with same name already present.')
        prnt(f'Update contact? (y,n) [y]: ', end='')
        if inp() == 'n':
            return
        pass
    else:
        contacts[name] = Contact(None, None)
    update_contact(name, True, True)
    pass

def read_addr(msg):
    prnt(msg, end='')
    dst_addr = inp()
    if dst_addr in contacts:
        if contacts[dst_addr].addr is None:
            prnt(f'[+] You did not provide a wallet address for {dst_addr} yet.')
            update_contact(dst_addr, True, False)
            pass
        dst_addr = contacts[dst_addr].addr
        pass
    return dst_addr

def read_pk_chat(msg):
    prnt(msg, end='')
    pk_chat = inp()
    if pk_chat in contacts:
        if contacts[pk_chat].pk_chat is None:
            prnt(f'[+] You did not provide a public chat key for {pk_chat} yet.')
            update_contact(pk_chat, False, True)
            pass
        return contacts[pk_chat].pk_chat
    return bytes.fromhex(pk_chat)

def chatmsg2chatnonce(msg: ChatMsg) -> ChatNonce:
    global CHATKEY, SIGNKEY
    if msg is None:
        return None
    msg_bytes = None
    if not msg.msg is None:
        msg_bytes = msg.msg.encode('ascii')
        pass
    pass
    return ChatNonce(
        sk_A=CHATKEY.sk,
        pk_B=msg.rcv,
        vk_A=bytes.fromhex(SIGNKEY.public_key),
        msg_chat=msg_bytes
    )

def send_xrp(msg: ChatMsg = None):
    global WALLET, SIGNKEY
    dst_addr = read_addr('Tx destination address or contact name: ')
    prnt('Tx amount: ', end='')
    try:
        amnt = int(inp())
    except ValueError as e:
        prnt(f'[!] Error: {e}')
        return
    nonce = chatmsg2chatnonce(msg)
    tx_hash = pay(WALLET, SIGNKEY, amnt, dst_addr, nonce)
    pass

def send_msg():
    global WALLET, SIGNKEY
    prnt('Message: ', end='')
    msg = inp().strip()
    rcvr = read_pk_chat('Message receiver key or contact name: ')
    if not len(msg) % 32 == 0:
        msg += ' ' * (32 - (len(msg) % 32))
        pass
    assert len(msg) % 32 == 0
    for i in range(0, len(msg), 32):
        send_xrp(msg=ChatMsg(msg[i:i+32], rcvr))
        pass
    prnt(f'[+] Message sent.')
    prnt(f'[+] Leaking nonce...')
    nonce = chatmsg2chatnonce(ChatMsg(None, rcvr))
    new_signkey = Wallet.create(CryptoAlgorithm.SECP256K1)
    set_sign_key(WALLET, new_signkey, old_signkey=SIGNKEY, nonce=nonce)
    SIGNKEY = new_signkey
    pass

def recv_msg():
    global WALLET, chats
    addr = read_addr('Mailbox address or contact name: ')
    pk_chat = read_pk_chat('Message sender key or contact name: ')
    txs = get_payment_transactions(addr)
    for tx in txs:
        srks = get_regularkey_transactions(tx.account)
        sk, vk, k_chat, curve = b'\x00', b'\x00', b'\x00', None
        for srk in srks:
            if srk.signing_pub_key != tx.signing_pub_key:
                continue
            vk, k_chat, curve = has_amsg(CHATKEY.sk, pk_chat, srk)
            if vk == b'\x00':
                continue
            sk = recover_sk(curve, k_chat, vk, srk)
            if sk != b'\x00':
                break
            pass
        if sk == b'\x00':
            continue
        txs_ac = list()
        for tx_ac in txs:
            if tx_ac.account == tx.account and tx_ac.destination == tx.destination:
                txs_ac.append(tx_ac)
                pass
            pass
        amsg_parts = list()
        for tx_ac in txs_ac:
            idx, amsg = recover_msg(curve, k_chat, sk, tx_ac)
            if not amsg == '':
                amsg_parts.append((idx, amsg))
                pass
            pass
        amsg_parts = list(sorted(amsg_parts, key=lambda el: el[0]))
        if len(amsg_parts) > 0:
            if not pk_chat in chats:
                chats[pk_chat] = list()
                pass
            idx, _ = amsg_parts[0]
            amsg = ''.join([amsg for _, amsg in amsg_parts])
            chats[pk_chat].append((idx, amsg.strip()))
        pass
    if pk_chat in chats:
        for _, msg in sorted(chats[pk_chat], key=lambda el: el[0]):
            prnt(f'{pk_chat.hex()}: {msg}')
            pass
        pass
    else:
        prnt(f'No messages from {pk_chat.hex()}.')
        pass
    pass



if __name__ == '__main__':
    global WALLET, CHATKEY, SIGNKEY
    from xrpl.wallet import Wallet
    from xrpl.constants import CryptoAlgorithm
    connect("https://s.altnet.rippletest.net:51234/")
    
    prnt('** Ripple Chat **\n')
    prnt('Please enter a seed for your chat keys [new]: ', end='')
    seed = inp()
    if seed == '':
        tmp = Wallet.create(CryptoAlgorithm.SECP256K1)
        pass
    else:
        tmp = Wallet(seed, 0)
        pass
    CHATKEY = ChatKey(bytes.fromhex(tmp.private_key), bytes.fromhex(tmp.public_key), tmp.seed)
    prnt('Please enter a seed for your wallet [new]: ', end='')
    seed = inp()
    if seed == '':
        WALLET = Wallet.create(CryptoAlgorithm.SECP256K1)
        pass
    else:
        WALLET = Wallet(seed, 0)
        pass
    fund_wallet(WALLET)
    SIGNKEY = Wallet.create(CryptoAlgorithm.SECP256K1)
    set_sign_key(WALLET, SIGNKEY)

    prnt('[+] Wallet created and funded.')
    prnt('')
    print_info()

    halt = False
    while not halt:
        prnt('')
        prnt('[+] Main menu:')
        prnt('[+]   1 Print balance')
        prnt('[+]   2 Send XRP')
        prnt('[+]   3 Embed hidden message')
        prnt('[+]   4 Receive embedded message')
        prnt('[+]   6 Show contact information')
        prnt('[+]   7 Add contact')
        prnt('[+]   8 Show wallet information')
        prnt('[+]   9 Print private information *DANGEROUS*')
        prnt('[+]   0 Exit')
        prnt('Choose an option: ', end='')
        inpt = inp()
        if inpt == '0':
            halt = True
        elif inpt == '1':
            prnt(f'[+] balance: {get_balance(WALLET.classic_address)}')
        elif inpt == '2':
            send_xrp()
        elif inpt == '3':
            send_msg()
        elif inpt == '4':
            recv_msg()
        elif inpt == '6':
            show_contact()
        elif inpt == '7':
            add_contact()
        elif inpt == '8':
            print_info(False)
        elif inpt == '9':
            print_info(True)
        else:
            pass
        pass
    pass
