from bit import PrivateKeyTestnet, ChatMsg
from bit.exceptions import InsufficientFunds
from receive import receive

'''
    Catch Deprecation Warnings
'''
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning) 

btc_sk = PrivateKeyTestnet()
#btc_sk = PrivateKeyTestnet.from_hex('89a68208c2fc9763e77b3b417ff8c3669855013ce0cc27cecef4bc5dd3223cd4')
btc_vk = btc_sk.public_key
btc_addr = btc_sk.address
chat_sk = PrivateKeyTestnet()
#chat_sk = PrivateKeyTestnet.from_hex('06e8923ded03757600f42e8d63b73f829490e139d8231618ff3b7a5500896fa7')
chat_pk = chat_sk.public_key
mailbox_addr = 'tb1q0dtylempzqref95sy8zv9c3ra2x4a7sv45ecy7'

contacts = dict()

def add():
    name = input('Name: ')
    address = input('Chat Address: ')
    contacts[name] = address
    pass

def balance():
    print(f'{btc_sk.get_balance()} satoshi')
    pass

def clear():
    print(f'tx id: {btc_sk.send([(mailbox_addr, 1, "satoshi")], leftover=mailbox_addr, unspents=btc_sk.get_unspents())}')
    pass

def print_contacts():
    print(f'You have {len(contacts)} contacts:')
    for i, contact in enumerate(contacts):
        print(f'\t{i+1}: {contact} ({contacts[contact]})')
        pass
    pass

def hello():
    global mailbox_addr
    print(f'Welcome to BTC-CHAT.')
    mb = input(f'Which mailbox address would you like to use today?\nmailbox address [{mailbox_addr}]: ')
    if mb != '':
        mailbox_addr = mb
        pass
    print(f"Info:")
    print(f"")
    print(f"    Mailbox Address: {mailbox_addr}")
    print(f"")
    print(f"     Wallet Address: {btc_addr}")
    #print(f"  Wallet Public Key: {btc_vk.hex()}")
    #print(f"  Wallet Secret Key: {btc_sk.to_hex()}")
    print(f"")
    print(f"       Chat Address: {chat_pk.hex()}")
    #print(f"    Chat Secret Key: {chat_sk.to_hex()}")
    print(f"")
    print(f"If you need help, type '?' or 'help'.")
    pass

def help():
    print(f'''
This is the help message.

The following commands are available:

    ?:              Print this help message
    add contact:    Add a contact to the Chat address book
    balance:        Show the account balance of your Bitcoin wallet
    clear account:  Clear the Bitcoin account by sending all available BTC to the mailbox address
    contacts:       Show all contacts in you address book
    exit:           Exit the chat client
    help:           Alias for '?'
    mailbox:        Change the mailbox address
    quit:           Alias for 'exit'
    receive chat:   Receive all chat messages of a specific conversation
    send chat:      Send a message to someone
    send btc:       Send bitcoin to some wallet
    show addr:      Print your bitcoin address and show it as QR code if a display is available
    show address:   Alias for 'show addr'
    utxos:          Show all Unspent Transaction Outputs associated with your wallet
    ''')
    pass

def mailbox():
    global mailbox_addr
    mb = input(f'new mailbox address [{mailbox_addr}]: ')
    if mb != '':
        mailbox_addr = mb
        pass
    pass

def rcv_chat():
    global chat_sk, chat_pk, mailbox_addr
    name = input('Name: ')
    if name in contacts:
        sender = contacts[name]
        pass
    else:
        sender = input('Chat address: ')
        contacts[name] = sender
        pass
    receive(mailbox_addr, chat_sk.to_hex(), sender)
    pass

def send_chat():
    global btc_sk, btc_vk, btc_addr, mailbox_addr
    name = input('Name: ')
    if name in contacts:
        rcvr_addr = contacts[name]
        pass
    else:
        rcvr_addr = input('Chat address: ')
        contacts[name] = rcvr_addr
        pass
    msg = input('message: ')
    amsg = ChatMsg(chat_sk.to_hex(), rcvr_addr, msg, btc_vk.hex())
    if len(amsg.nonces) > len(btc_sk.get_unspents()):
        print('[ERROR] Cannot send message: Not enough unspents.')
        return
    change_sk = PrivateKeyTestnet()
    change_vk = change_sk.public_key
    change_addr = change_sk.address
    try:
        tx_id = btc_sk.send([(mailbox_addr, 1, "satoshi")], leftover=change_addr, unspents=btc_sk.get_unspents(), chat_msg=amsg)
        pass
    except ValueError:
        print(f'[ERROR] Cannot send 1 to {mailbox_addr}: Not enough satoshi.')
        return
    except ConnectionError:
        print(f'[ERROR] All APIs are unreachable. Please try again later.')
        return
    print(amsg, f'in tx {tx_id}')
    btc_sk = change_sk
    btc_vk = change_vk
    btc_addr = change_addr
    print(f'New Wallet Secret Key: {btc_sk.to_hex()}')
    print(f'New Wallet Address: {btc_addr}')
    pass

def send_btc():
    rcvr_addr = input('BTC address: ')
    val = input('value (satoshi): ')
    try:
        print(f'tx id: {btc_sk.send([(rcvr_addr, val, "satoshi")])}')
        pass
    except ValueError as err:
        print(f'[ERROR] Value Error: {err}')
        pass
    except InsufficientFunds as err:
        print(f'[ERROR] Insufficient funds: {err}')
        pass
    pass

def show_addr():
    import qrcode
    try:
        qrcode.make(btc_addr).show()
        pass
    except:
        print('[ERROR] Cannot connect to display.')
        pass
    print(f'Wallet Address: {btc_addr}')
    pass

def utxos():
    utxos = btc_sk.get_unspents()
    print(f'You have {len(utxos)} unspent outputs:')
    for i, utxo in enumerate(utxos):
        print(f'\t{i+1}: {utxo.amount} satoshi')
        pass
    pass

if __name__ == '__main__':
    hello()
    while True:
        try:
            cmd = input('> ')
            pass
        except (EOFError, KeyboardInterrupt):
            print('exit')
            break
        try:
            if cmd == 'add contact':
                add()
                pass
            elif cmd == 'balance':
                balance()
                pass
            elif cmd == 'clear account':
                clear()
                pass
            elif cmd == 'contacts':
                print_contacts()
                pass
            elif cmd == 'exit' or cmd == 'quit':
                break
            elif cmd == 'help' or cmd == '?':
                help()
                pass
            elif cmd == 'mailbox':
                mailbox()
                pass
            elif cmd == 'receive chat':
                rcv_chat()
                pass
            elif cmd == 'send chat':
                send_chat()
                pass
            elif cmd == 'send btc':
                send_btc()
                pass
            elif 'show addr' in cmd:
                show_addr()
                pass
            elif cmd == 'utxos':
                utxos()
                pass
            pass
        except KeyboardInterrupt:
            print()
            pass
        pass
    pass
