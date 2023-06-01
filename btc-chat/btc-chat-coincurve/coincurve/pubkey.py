from typing import Tuple

from coincurve.context import GLOBAL_CONTEXT, Context
from coincurve.ecdsa import der_to_cdata, deserialize_recoverable, recover
from coincurve.flags import EC_COMPRESSED, EC_UNCOMPRESSED
from coincurve.types import Hasher
from coincurve.utils import (
    bytes_to_int,
    int_to_bytes_padded,
    pad_scalar,
    sha256,
    validate_secret,
)

from ._libsecp256k1 import ffi, lib

class PublicKey:
    def __init__(self, data, context: Context = GLOBAL_CONTEXT):
        """
        :param data: The formatted public key. This class supports parsing
                     compressed (33 bytes, header byte `0x02` or `0x03`),
                     uncompressed (65 bytes, header byte `0x04`), or
                     hybrid (65 bytes, header byte `0x06` or `0x07`) format public keys.
        :type data: bytes
        :param context:
        :raises ValueError: If the public key could not be parsed or was invalid.
        """
        if not isinstance(data, bytes):
            self.public_key = data
        else:
            public_key = ffi.new('secp256k1_pubkey *')

            parsed = lib.secp256k1_ec_pubkey_parse(context.ctx, public_key, data, len(data))

            if not parsed:
                raise ValueError('The public key could not be parsed or is invalid.')

            self.public_key = public_key

        self.context = context

    @classmethod
    def from_secret(cls, secret: bytes, context: Context = GLOBAL_CONTEXT):
        """
        Derive a public key from a private key secret.

        :param secret: The private key secret.
        :param context:
        :return: The public key.
        :rtype: PublicKey
        """
        public_key = ffi.new('secp256k1_pubkey *')

        created = lib.secp256k1_ec_pubkey_create(context.ctx, public_key, validate_secret(secret))

        if not created:  # no cov
            raise ValueError(
                'Somehow an invalid secret was used. Please '
                'submit this as an issue here: '
                'https://github.com/ofek/coincurve/issues/new'
            )

        return PublicKey(public_key, context)

    @classmethod
    def from_valid_secret(cls, secret: bytes, context: Context = GLOBAL_CONTEXT):
        public_key = ffi.new('secp256k1_pubkey *')

        created = lib.secp256k1_ec_pubkey_create(context.ctx, public_key, secret)

        if not created:
            raise ValueError('Invalid secret.')

        return PublicKey(public_key, context)

    @classmethod
    def from_point(cls, x: int, y: int, context: Context = GLOBAL_CONTEXT):
        """
        Derive a public key from a coordinate point in the form `(x, y)`.

        :param x:
        :param y:
        :param context:
        :return: The public key.
        :rtype: PublicKey
        """
        return PublicKey(b'\x04' + int_to_bytes_padded(x) + int_to_bytes_padded(y), context)

    @classmethod
    def from_signature_and_message(
        cls, signature: bytes, message: bytes, hasher: Hasher = sha256, context: Context = GLOBAL_CONTEXT
    ):
        """
        Recover an ECDSA public key from a recoverable signature.

        :param signature: The recoverable ECDSA signature.
        :param message: The message that was supposedly signed.
        :param hasher: The hash function to use, which must return 32 bytes. By default,
                       the `sha256` algorithm is used. If `None`, no hashing occurs.
        :param context:
        :return: The public key that signed the message.
        :rtype: PublicKey
        :raises ValueError: If the message hash was not 32 bytes long or recovery of the ECDSA public key failed.
        """
        return PublicKey(
            recover(message, deserialize_recoverable(signature, context=context), hasher=hasher, context=context)
        )

    @classmethod
    def combine_keys(cls, public_keys, context: Context = GLOBAL_CONTEXT):
        """
        Add a number of public keys together.

        :param public_keys: A sequence of public keys.
        :type public_keys: List[PublicKey]
        :param context:
        :return: The combined public key.
        :rtype: PublicKey
        :raises ValueError: If the sum of the public keys was invalid.
        """
        public_key = ffi.new('secp256k1_pubkey *')

        combined = lib.secp256k1_ec_pubkey_combine(
            context.ctx, public_key, [pk.public_key for pk in public_keys], len(public_keys)
        )

        if not combined:
            raise ValueError('The sum of the public keys is invalid.')

        return PublicKey(public_key, context)

    def format(self, compressed: bool = True) -> bytes:
        """
        Format the public key.

        :param compressed: Whether or to use the compressed format.
        :return: The 33 byte formatted public key, or the 65 byte formatted public key if `compressed` is `False`.
        """
        length = 33 if compressed else 65
        serialized = ffi.new('unsigned char [%d]' % length)
        output_len = ffi.new('size_t *', length)

        lib.secp256k1_ec_pubkey_serialize(
            self.context.ctx, serialized, output_len, self.public_key, EC_COMPRESSED if compressed else EC_UNCOMPRESSED
        )

        return bytes(ffi.buffer(serialized, length))

    def point(self) -> Tuple[int, int]:
        """
        :return: The public key as a coordinate point.
        """
        public_key = self.format(compressed=False)
        return bytes_to_int(public_key[1:33]), bytes_to_int(public_key[33:])

    def verify(self, signature: bytes, message: bytes, hasher: Hasher = sha256) -> bool:
        """
        :param signature: The ECDSA signature.
        :param message: The message that was supposedly signed.
        :param hasher: The hash function to use, which must return 32 bytes. By default,
                       the `sha256` algorithm is used. If `None`, no hashing occurs.
        :return: A boolean indicating whether or not the signature is correct.
        :raises ValueError: If the message hash was not 32 bytes long or the DER-encoded signature could not be parsed.
        """
        msg_hash = hasher(message) if hasher is not None else message
        if len(msg_hash) != 32:
            raise ValueError('Message hash must be 32 bytes long.')

        verified = lib.secp256k1_ecdsa_verify(self.context.ctx, der_to_cdata(signature), msg_hash, self.public_key)

        # A performance hack to avoid global bool() lookup.
        return not not verified

    def add(self, scalar: bytes, update: bool = False):
        """
        Add a scalar to the public key.

        :param scalar: The scalar with which to add.
        :param update: Whether or not to update and return the public key in-place.
        :return: The new public key, or the modified public key if `update` is `True`.
        :rtype: PublicKey
        :raises ValueError: If the tweak was out of range or the resulting public key was invalid.
        """
        scalar = pad_scalar(scalar)

        new_key = ffi.new('secp256k1_pubkey *', self.public_key[0])

        success = lib.secp256k1_ec_pubkey_tweak_add(self.context.ctx, new_key, scalar)

        if not success:
            raise ValueError('The tweak was out of range, or the resulting public key is invalid.')

        if update:
            self.public_key = new_key
            return self

        return PublicKey(new_key, self.context)

    def multiply(self, scalar: bytes, update: bool = False):
        """
        Multiply the public key by a scalar.

        :param scalar: The scalar with which to multiply.
        :param update: Whether or not to update and return the public key in-place.
        :return: The new public key, or the modified public key if `update` is `True`.
        :rtype: PublicKey
        """
        scalar = validate_secret(scalar)

        new_key = ffi.new('secp256k1_pubkey *', self.public_key[0])

        lib.secp256k1_ec_pubkey_tweak_mul(self.context.ctx, new_key, scalar)

        if update:
            self.public_key = new_key
            return self

        return PublicKey(new_key, self.context)

    def combine(self, public_keys, update: bool = False):
        """
        Add a number of public keys together.

        :param public_keys: A sequence of public keys.
        :type public_keys: List[PublicKey]
        :param update: Whether or not to update and return the public key in-place.
        :return: The combined public key, or the modified public key if `update` is `True`.
        :rtype: PublicKey
        :raises ValueError: If the sum of the public keys was invalid.
        """
        new_key = ffi.new('secp256k1_pubkey *')

        combined = lib.secp256k1_ec_pubkey_combine(
            self.context.ctx, new_key, [pk.public_key for pk in public_keys], len(public_keys)
        )

        if not combined:
            raise ValueError('The sum of the public keys is invalid.')

        if update:
            self.public_key = new_key
            return self

        return PublicKey(new_key, self.context)

    def __eq__(self, other) -> bool:
        return self.format(compressed=False) == other.format(compressed=False)
