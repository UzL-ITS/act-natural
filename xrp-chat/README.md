XRP-Chat
========

This folder provides a Python 3 PoC implementation of the chat over a subliminal channel in Ripple proposed in **'Act natural!: Having a Private Chat on a Public Blockchain'**.

Build
-----

In order to use the chat client you need to install [*xrpl-py*](https://github.com/XRPLF/xrpl-py) in the [`xrpl-py`](./xrpl-py/) folder and [*ECPy*](https://github.com/cslashm/ECPy) in the [`ecpy`](./ecpy/) folder.

To install our version of *xrpl-py* and *ECPy* you can either run

```text
$ ./install.sh
```

directly or run `pip install --user .` manually in both folders. Either way, the library will not be installed system-wide but for the current user only.

Using the chat client
--------------------

Besides our modified versions of *xrpl-py* and *ECPy*, the PoC relies on the following Python libraries: *collections*, *datetime*, *hashlib*, *PyCryptodomex*. All but *PyCryptodomex* should be pre-installed with your Python installation. To install *PyCryptodomex* run:

```text
$ pip3 install --user pycryptodomex
```

Afterward, you can run the PoC with

```text
$ cd chat-client
$ python chat.py 
** Ripple Chat **

Please enter a seed for your chat keys [new]: 
```

Here you can either provide a well-formated seed or let the application create a new pair of chat keys by pressing enter.

Next, the same prompt appears for the wallet key pair. Again, either provide a well-formatted seed value or press enter for a new random key pair. The wallet will be created and funded. When this initial step is done, the program outputs all important public information and a menu of options on how to proceed:

```text
[+] Old signing key: -None-
[+] New signing key: 03D6F7AA1CEBC43B9F3698404136D1DB9C826176EED8480BAD6FC84BC671C8CFFB
[+] Hash: 5AF902B2240A7075844900D52084438C54A74A58D41091D4ABD117ADF0D330E1
[+] Sig:  3045022100E1F378AEEC442D1A0D55FC6864D5619970C942E23B57FDF67389C14C8AABB7C002201FFE1787E48F1628F8B9575232D26B9A48635C891AB9F6FEAFF610F31154F536
[+] Wallet created and funded.

Chat public key:            037B112A02DA4357BB3E181BA1856F7CCED7F6A6D525435D122E8E4616F1A57D55
Chat private key:           -HIDDEN-
Wallet public master key:   02F364ADE59BBF27A8167A640D681712A3D0BC25D0FFD5AF76A40C6F8AA376E74D
Wallet private master key:  -HIDDEN-
Wallet public sign key:     03D6F7AA1CEBC43B9F3698404136D1DB9C826176EED8480BAD6FC84BC671C8CFFB
Wallet private sign key:    -HIDDEN-
Wallet address:             r9eHFz97BnQzCxGzMoXP8f5hGLB97V5WFT

[+] Main menu:
[+]   1 Print balance
[+]   2 Send XRP
[+]   3 Embed hidden message
[+]   4 Receive embedded message
[+]   6 Show contact information
[+]   7 Add contact
[+]   8 Show wallet information
[+]   9 Print private information *DANGEROUS*
[+]   0 Exit
Choose an option: 
```

* Option 1 prints the wallet's current XRP balance.
* Option 2 lets you send XRP. You will be prompted for the address and the amount.
* Option 3 lets you embed a hidden message in one or more transactions. You will be prompted for the message and the receivers public chat key. Then, you will be prompted for an address that will receive the transaction and the amount you want to send for as many times as it takes to send the message.
* Option 4 lets you receive all messages sent from a certain chat key to a certain mailbox address. You will be prompted for the mailbox address and the message sender's public chat key.
* Option 5 is not implemented.
* Option 6 prints your contact information.
* Option 7 lets you add or modify contacts. You will be prompted for the contact information to store.
* Option 8 prints the public key information like during startup.
* Option 9 prints the same information as option 8 but also shows the private keys. **Be careful here**
* Option 0 closes the chat program.

Sending a message
-----------------

To send a message you need an account balance greater than 10 XRP. You can check your balance by choosing option 1:

```text
Choose an option: 1
[+] balance: 999999990
```

You can then send a message with option 3:

```text
Choose an option: 3
Message: Hi Bob, how are you?
Message receiver key or contact name: 026BF3E2FA62AB97F42514367AC4F5BD2313659AC9585A91F2A81637A4C75AB7D6
Tx destination address or contact name: rfUrC4YwgLXUSLJd52gbr3we3m36Hx9g4G
Tx amount: 1337
[+] Tx: rU96ontawSpF3QqPUewfrCaE2XCV3nKPaM -> rfUrC4YwgLXUSLJd52gbr3we3m36Hx9g4G (1337 XRP)
[+] Hash: A28DED815C82D90B55374403DF8CB4DA267905651E6097C16701FF85A8257E5C
[+] Sig:  30440220281AE0C99EE4D29F8CC7B6781A60699C62E5C98FEB0AD3D37D48983DEC56AAA502200C21B2907AEAB65021572FA2714B74B9E2E190CE9B84D87746E3133A9EA76A2C
[+] Message sent.
[+] Leaking nonce...
[+] Old signing key: 03EAB90A66311B8B1C8F70F3D3A16287ED0F1A602F557787A3B1D2D4F740444F9D
[+] New signing key: 02548768E0080D19240AA25B9392E667DFD54660327D497A7B4F05DE2C76C3CC80
[+] Hash: CB48553F416F733CA507CDBEE11E61F9DDF3AC67573E9BAFA2292CC123E6AD87
[+] Sig:  3044022056487DFFAD80ACFAFD73D02BF1B6B0817CE1CB8865005B8C4213403E81142389022072E11ED21681F38063EDCEB0EE69E7A1B0C98485DB5D06E123AC738A4455E18A
```

Receiving a message
-------------------

Receiving a message works independent of your account balance. You only have to provide the mailbox address and the sender's public chat key:

```text
Choose an option: 4
Mailbox address or contact name: rfUrC4YwgLXUSLJd52gbr3we3m36Hx9g4G
Message sender key or contact name: 02730FE8D6939E096DBADBE6A087ADD2A376933F62F75B55C3D7FF52A7C68962F6
02730fe8d6939e096dbadbe6a087add2a376933f62f75b55c3d7ff52a7c68962f6: Hi Bob, how are you?
```

Version information and patches
-------------------------------

We forked the libraries at the following commits:

* *xrpl-py*: [`b3130ca7a991984266b6b74e87ccafdb7490ca7e`](https://github.com/XRPLF/xrpl-py/tree/b3130ca7a991984266b6b74e87ccafdb7490ca7e)
* *ECPy*: [`8143d9ac017de0cb7f980bedaf56cefe6b4d9180`](https://github.com/cslashm/ECPy/tree/8143d9ac017de0cb7f980bedaf56cefe6b4d9180)

The patches we applied can be found in the [`patches`](./patches/) folder. The subfolders contain patches for each single file we altered. The `<lib>.patch` files contain the concatenation of all single file patches. We generated the patches using the `patches_gen.sh` script.

Notes
-----

Currently, messages can only be embedded into ECDSA signatures. EdDSA embeddings will be added soon.
