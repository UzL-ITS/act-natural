# BTC-Chat

This repository provides a Python 3 PoC implementation of the chat over a subliminal channel in Bitcoin proposed in **'Act natural!': Having a Private Chat on a Public Blockchain**.

## Build

In order to use the chat client you need to compile our forks of [*libsecp256k1*](https://github.com/bitcoin-core/secp256k1) in the [`btc-chat-secp256k1`](btc-chat-secp256k1) folder, [*coincurve*](https://github.com/ofek/coincurve) in the [`btc-chat-coincurve`](btc-chat-coincurve) folder, and [*bit*](https://github.com/ofek/bit) in the [`btc-chat-bit`](btc-chat-bit) folder.

Please make sure that a symbolic link with the name `libsecp256k1` in the [`btc-chat-coincurve`](btc-chat-coincurve) folder points to the [`btc-chat-libsecp256k1`](btc-chat-libsecp256k1) folder before building *coincurve*.
You can use the following commands to achieve this: 

```bash
$ cd btc-chat-coincurve
$ ln -s ../btc-chat-secp256k1/ libsecp256k1
$ cd ..
```

To install our version of *bit* **and** *coincurve* using *libsecp256k1* you can either run

```bash
$ ./update_bit_installation.sh
```

directly or follow the steps performed in the script.
The script will first uninstall *coincurve* and *bit* if present in the system.
Then *coincurve* will be build and installed as a user's library before building and installing *bit* as a user's library.
During the build step of *coincurve*, *libsecp256k1* will be compiled to be used with *coincurve*.

If you only want to use our modified libsecp256k1 in order to run the benchmarks, you can compile it directly by following the [build steps](https://github.com/bitcoin-core/secp256k1#build-steps) in the official repository.
Alternatively, you can use the provided script `compile_libsecp256k1.sh` which additionally creates a folder `benchmark` and copies all benchmark programs used in the paper to this folder.

## Using the chat client

Besides our modified versions of *bit*, *coincurve*, and *libsecp256k1*, the PoC relies on the following Python libraries: *sagemath*, *pycryptodomex*, *bitcoinlib*, and *qrcode*.
If you miss any of them, you can install them by running

```bash
$ pip3 install --user <library name>
```

Afterward, you can run the PoC with

```bash
$ cd chat-client
$ python chat-client.py 
Welcome to BTC-CHAT.
Which mailbox address would you like to use today?
mailbox address [tb1q0dtylempzqref95sy8zv9c3ra2x4a7sv45ecy7]: 
```

Here you can choose a mailbox address to use when sending messages.
The mailbox address will receive 1 Satoshi.
A receiver has to configure the same mailbox address to enable the PoC to receive messages.
If you don't want to change the default mailbox address just press Enter.
The chat client then presents you the current settings.

```text
Info:
   Wallet Address: n4ANv4Zvb4yJXP4zYTdxBmjpKwAC9rt3Uz
  Mailbox Address: tb1q0dtylempzqref95sy8zv9c3ra2x4a7sv45ecy7
     Chat Address: 02cc42ad8f0cf4b741ae7a0f772a4a128bad61fbf661940fcf511ce858ad38abab

If you need help, type '?' or 'help'.

>
```

On each start, the client generates a new random walles secret key and a new random chat secret key.
If you want any of the keys to have a certain value you have to change the source code in [`chat-client.py`](chat-client/chat-client.py) in lines [12/13](chat-client/chat-client.py#L12) and [17/18](chat-client/chat-client.py#17) before starting the program.

### Sending a message

In order to send a message your wallets needs sufficiently many UTXOs.
You can check your UTXOs with the `utxos` command.
To ease sending BTC to your wallet you can display your wallets address as a qr-code. To do so use the `show addr` command.

Sending a chat message then works as follows:

```text
> send chat
Name: bob
Chat address: 023635efd4e4aad8a4957b49edbdd8fd0ac30999290ffbdbcba26abe2207b48ff5
message: Hi Bob, how are you?
To 023635efd4e4aad8a4957b49edbdd8fd0ac30999290ffbdbcba26abe2207b48ff5: "Hi Bob, how are you?            " in tx a0a16f7960249857a5df6d6129852f28472373948b0179006c44cbb364057d10
New Wallet Secret Key: ***DELETED***
New Wallet Address: mvSPDKDufC983cL7d3sW7hhaJ43hkz659Q
>
```

### Receiving a message

Receiving a message works independent of your wallets balance.
But you have to make sure that the right mailbox address is configured.
You can check and set the mailbox address using the `mailbox` command.

Receiving messages works as follows:

```text
> receive chat
Name: bob
Chat address: 023635efd4e4aad8a4957b49edbdd8fd0ac30999290ffbdbcba26abe2207b48ff5
023635efd4e4aad8a4957b49edbdd8fd0ac30999290ffbdbcba26abe2207b48ff5: I'm great! This chat is nice. We're hiding in the open.          in tx f9ba5b50b0dc813f680595c1e813d5313743773370becac04312ce994ce8a13e
023635efd4e4aad8a4957b49edbdd8fd0ac30999290ffbdbcba26abe2207b48ff5: Hi Bob, how are you?             in tx a0a16f7960249857a5df6d6129852f28472373948b0179006c44cbb364057d10
>
```

*Note*: We use the NetworkAPI implemented in the *bit* python package.
Some of the API backends used by *bit* only return transactions that are part of a block but not those transactions that are not mined yet.
If such a backend is chosen by *bit*, you have to wait for about 10 minutes before you can receive the message.
This behavior is API dependent and not caused by our message embedding technique.

## Running the benchmarks

If you want to run the benchmarks you have to compile our version of *libsecp256k1*.
If you use the provided script [`compile_libsecp256k1.sh`](compile_libsecp256k1.sh) you find all benchmark programs in the `benchmark` folder.
If you follow the official *libsec256k1* build instructions the binaries can be found in `btc-chat-secp256k1`.

The benchmarks in the paper were generated using

```bash
$ SECP256K1_BENCH_ITERS=1000000 ./bench_[aesni,sha256,ecdh,nonceGen,ecdsa_sign]
```

The default number of iterations is `20000`.
The command above overwrites the default by setting the number of iterations to `1000000`.

## Version information and patches

We forked the libraries at the following commits:

* *secp256k1*: [`4c3ba88c3a869ae3f45990286c79860539a5bff8`](https://github.com/bitcoin-core/secp256k1/tree/4c3ba88c3a869ae3f45990286c79860539a5bff8)
* *coincurve*: [`0bb42ce2d97e7ded8181b10e6a96122865c9854f`](https://github.com/ofek/coincurve/tree/0bb42ce2d97e7ded8181b10e6a96122865c9854f) (tag: v15.0.0)
* *bit*: [`776f97ae7f9b3f05157113abc913eb141b2817ee`](https://github.com/ofek/bit/commit/776f97ae7f9b3f05157113abc913eb141b2817ee)

The patches we applied can be found in the [`patches`](patches) folder.
The subfolders contain patches for each single file we altered.
The `<lib>.patch` files contain the concatenation of all single file patches.
We generated the patches using the `patches_gen.sh` script.
