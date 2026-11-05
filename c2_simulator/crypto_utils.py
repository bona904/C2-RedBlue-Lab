# c2_simulator/crypto_utils.py


def xor_encrypt(data: bytes, key: int = 0x5A) -> bytes:
    """异或加密：对每个字节与 key 异或。

    异或两次可还原（a ^ k ^ k == a），所以加解密是同一个函数。
    """
    return bytes(b ^ key for b in data)


def xor_decrypt(data: bytes, key: int = 0x5A) -> bytes:
    """异或解密：直接复用加密函数。

    因为异或两次可还原，所以加解密同一函数。
    """
    return xor_encrypt(data, key)