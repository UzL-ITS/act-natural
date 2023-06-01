from typing import Tuple

from ._libsecp256k1 import ffi, lib

class ChatNonce:
    def __init__(self, sk_A: bytes = None, pk_B: bytes = None, vk_A: bytes = None, msg_chat: bytes = None):
        self.msg_chat = msg_chat
        self.pk_B = pk_B
        self.sk_A = sk_A
        self.vk_A = vk_A
        self.struct = self.as_struct()
        pass

    def as_struct(self):
        if self.pk_B is None or self.sk_A is None or self.vk_A is None:
            return (ffi.NULL, ffi.NULL)
        struct = ffi.new('secp256k1_chat_data *')
        if self.msg_chat is None:
            struct.msg_chat = ffi.NULL
            pass
        elif len(self.msg_chat) == 32:
            struct.msg_chat = ffi.from_buffer('unsigned char[32]', self.msg_chat)
            pass
        else:
            raise ValueError('[ERROR] The Chat message was neither None nor 32 bytes long.')
        struct.pk_B = ffi.from_buffer('unsigned char[33]', self.pk_B)
        struct.sk_A = ffi.from_buffer('unsigned char[32]', self.sk_A)
        struct.vk_A = ffi.from_buffer('unsigned char[33]', self.vk_A)
        return (lib.secp256k1_nonce_function_chat, struct)

    def __str__(self) -> str:
        if self.pk_B is None:
            return 'To NULL: NULL'
        elif self.msg_chat is None:
            return f'To {self.pk_B.hex()}: <SECRET KEY LEAKAGE>'
        return f'To {self.pk_B.hex()}: "{self.msg_chat.decode("ascii")}"'

    def __repr__(self) -> str:
        return self.__str__()

    pass
