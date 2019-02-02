import subprocess
from Crypto.Cipher import AES


# these are duplicate functions from gameserver.py - consider creating a utility.py to share them
# convert a bytes-like input into a hex-string
def bytes_to_hex(input_bytes):
    return "".join("{:02X}".format(b) for b in input_bytes)


# convert an integer into a series of little-endian bytes
def int_to_bytes(input_integer, size):
    # LSB on left (little endian)
    output_bytes = bytearray()
    for i in range(size):
        output_bytes.append(input_integer & 0xff)
        input_integer = input_integer >> 8
    return output_bytes
# end duplicate utilities


# left rotate a DWORD n by b bits
def left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff


def get_dynamic_key_legacy(username, password, auth_token):
    # expected result for "admin", "password", 0D2B5728
    # 8D2B5728050000000800000061646D696E000000000000000000000070617373776F72640000000000000000
    # expected response = 966EFFC3DE3AD8B02CC918D16923E8FB
    result = bytearray()
    result.extend(auth_token)
    result.append(len(username))
    result.extend(bytes.fromhex("00" * 3))  # expects a dword
    result.append(len(password))
    result.extend(bytes.fromhex("00" * 3))  # expects a dword
    result.extend(username.encode("ascii"))
    result.extend(bytes.fromhex("00" * (16 - len(username))))  # expects 16 bytes
    result.extend(password.encode("ascii"))
    result.extend(bytes.fromhex("00" * (16 - len(password))))  # expects 16 bytes
    command = "".join("{:02X}".format(b) for b in result)
    response = subprocess.run(['gbsha1.exe', command], stdout=subprocess.PIPE).stdout.decode('utf-8')
    return bytes.fromhex(response)


def sha0_process_block(chunk):
    w = []
    # break 64-byte chunk to 16 big-endian DWORDs
    for i in range(16):
        chunk_byte1 = chunk[i * 4 + 3] << (0 * 8)
        chunk_byte2 = chunk[i * 4 + 2] << (1 * 8)
        chunk_byte3 = chunk[i * 4 + 1] << (2 * 8)
        chunk_byte4 = chunk[i * 4 + 0] << (3 * 8)
        w.append(chunk_byte1 | chunk_byte2 | chunk_byte3 | chunk_byte4)

    w.extend(bytes.fromhex("00" * (80 - 16)))
    # expand the 16 DWORDs into 80 DWORDs
    for i in range(16, 80):
        # left rotate 0 for SHA-0, left rotate 1 for SHA-1
        w[i] = left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 0)

    # actually mangle the data
    sha_h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

    a = sha_h[0]
    b = sha_h[1]
    c = sha_h[2]
    d = sha_h[3]
    e = sha_h[4]

    for i in range(80):
        k = 0
        f = 0

        if 0 <= i <= 19:
            # BODY_16_19
            f = d ^ (b & (c ^ d))
            k = 0x5A827999
        elif 20 <= i <= 39:
            # BODY_20_31, BODY_32_39
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif 40 <= i <= 59:
            # BODY_40_59
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        elif 60 <= i <= 79:
            # BODY_60_79
            f = b ^ c ^ d
            k = 0xCA62C1D6

        a, b, c, d, e = ((left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff, a, left_rotate(b, 30), c, d)

    # Add this chunk's hash to result
    sha_h[0] = (sha_h[0] + a) & 0xffffffff
    sha_h[1] = (sha_h[1] + b) & 0xffffffff
    sha_h[2] = (sha_h[2] + c) & 0xffffffff
    sha_h[3] = (sha_h[3] + d) & 0xffffffff
    sha_h[4] = (sha_h[4] + e) & 0xffffffff

    # changes a typical SHA-0 into "gunbound-sha" by removing 4 bytes and swapping the DWORD endian
    result = bytearray()
    for block_index in range(4):
        result.extend(int_to_bytes(sha_h[block_index], 4))

    return result


def get_dynamic_key(username, password, auth_token):
    # essentially sha-0, truncated to 16 bytes, with each DWORD chunk endian-flipped
    sha_state = bytearray()
    sha_state.extend(username.encode("ascii"))
    sha_state.extend(password.encode("ascii"))
    sha_state.extend(auth_token)

    # credentials never exceed 12+12+4=28 bytes, so we can go straight to the finalize operation
    message_bit_length = len(sha_state) * 8
    sha_state.append(0x80)  # append one bit
    sha_state.extend(bytes.fromhex("00" * (62 - len(sha_state))))  # 64 byte chunk, subtract 2 to store length (WORD)
    sha_state.append(message_bit_length >> 8)
    sha_state.append(message_bit_length & 0xFF)
    return sha0_process_block(sha_state)


def aes_decrypt_block(block, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(block)


def aes_encrypt_block(block, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block)


def gunbound_static_decrypt(block):
    # fixed key for username and first password block -- key is hardcoded
    return aes_decrypt_block(block, bytes.fromhex("FFB3B3BEAE97AD83B9610E23A43C2EB0"))


def gunbound_dynamic_decrypt_raw(blocks, username, password, auth_token):
    key = get_dynamic_key(username, password, auth_token)
    cipher = AES.new(key, AES.MODE_ECB)
    plain_unprocessed_bytes = cipher.decrypt(blocks)
    return plain_unprocessed_bytes


def gunbound_dynamic_encrypt_raw(plain_bytes, username, password, auth_token):
    key = get_dynamic_key(username, password, auth_token)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_bytes = cipher.encrypt(plain_bytes)
    return encrypted_bytes


def gunbound_dynamic_decrypt(blocks, username, password, auth_token, command):
    packet_command = 0x8631607E + command  # originally command - 0x79CE9F82, but inverted to avoid negative ops
    raw = gunbound_dynamic_decrypt_raw(blocks, username, password, auth_token)
    processed = bytearray()
    current_block_command = 0
    for i in range(len(blocks)):
        internal_128_bit_index = i % 16
        if internal_128_bit_index < 4:
            current_block_command |= raw[i] << internal_128_bit_index * 8
            if internal_128_bit_index == 3:
                if current_block_command != packet_command:
                    print("gunbound_dynamic_decrypt: command checksum mismatch")
                current_block_command = 0
        else:
            processed.append(raw[i])
    return processed


def gunbound_dynamic_encrypt(plain_bytes, username, password, auth_token, command):
    if len(plain_bytes) % 12 != 0:
        print("gunbound_dynamic_encrypt: bytes are not aligned to 12-byte boundary")
        return bytes.fromhex("DEADBEEF")
    packet_command = 0x8631607E + command  # originally command - 0x79CE9F82, but inverted to avoid negative ops
    packet_command_bytes = bytearray()
    packet_command_bytes.append((packet_command >> 0) & 0xFF)
    packet_command_bytes.append((packet_command >> 8) & 0xFF)
    packet_command_bytes.append((packet_command >> 16) & 0xFF)
    packet_command_bytes.append((packet_command >> 24) & 0xFF)
    processed = bytearray()
    for i in range(len(plain_bytes)):
        if i % 12 == 0:
            processed.extend(packet_command_bytes)
        processed.append(plain_bytes[i])
    encrypted_bytes = gunbound_dynamic_encrypt_raw(processed, username, password, auth_token)
    return encrypted_bytes


if __name__ == "__main__":
    # this can be run directly during testing
    print("sane")
    print(bytes_to_hex(gunbound_dynamic_decrypt(
        bytes.fromhex("32 42 48 43 9B 83 BD 5E 9E 87 9D 03 14 DD 01 7E 95 FF BE FA 7B 8A DD 4C C2 D5 12 E0 8C 60 33 E9 DA C5 6B D5 11 DF 94 83 57 DD F6 2B 5A D4 85 41 A8 8F 44 4B D3 E4 25 A4 24 80 96 99 12 26 80 72 65 06 01 7E 15 04 81 D6 F2 1C 94 66 71 E9 05 87 B0 D7 9B EE 30 C6 B5 97 B4 42 92 D0 4E 00 C0 D0"),
        "saneusername", "sanepassword", bytes.fromhex(" FF DC 30 80"), 0x3432)))

    print("ami")
    print(bytes_to_hex(gunbound_dynamic_decrypt(
        bytes.fromhex("07 EB 74 B1 D0 DA B9 36 1A 1A 53 14 03 97 3D 62 90 74 82 8E 89 60 EC 38 41 65 05 27 D4 0E B8 F3"),
        "amigos", "amigos", bytes.fromhex("62 EF 09 15"), 0x4412)))

    # testing pure-python implementation of get_dynamic_key
    test_user = "admin"
    test_pass = "password"
    test_token = bytes.fromhex("41414141")
    print("original:", bytes_to_hex(get_dynamic_key_legacy(test_user, test_pass, test_token)))
    print("new:    :", bytes_to_hex(get_dynamic_key(test_user, test_pass, test_token)))
    # original: BE2A74B94B45B8297A7916994C1AA3F9
    # p3:     : BE2A74B94B45B8297A7916994C1AA3F9
