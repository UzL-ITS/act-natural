class ChatNonce:
    def __init__(self, sk_A: bytes = None, pk_B: bytes = None, vk_A: bytes = None, msg_chat: bytes = None):
        self.msg_chat = msg_chat
        self.pk_B = pk_B
        self.sk_A = sk_A
        self.vk_A = vk_A
        pass

    def __str__(self) -> str:
        if self.pk_B is None:
            return 'To NULL: NULL'
        elif self.msg_chat is None:
            return f'To {self.pk_B.hex()}: <SECRET KEY LEAKAGE>'
        return f'To {self.pk_B.hex()}: "{self.msg_chat.decode("ascii")}"'

    def __repr__(self) -> str:
        return self.__str__()
