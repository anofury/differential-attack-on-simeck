from simeck import Simeck

# 将10进制转换成16进制输出
def print_test_vector(block_size, key_size, key, plain1, plain2, cipher):
    print('block_size: ', block_size)
    print('  key_size: ', key_size)
    print(' masterKey: ', hex(key)[2:].rstrip('L').zfill(int(key_size / 4)))
    print('plaintext1: ', hex(plain1)[2:].rstrip('L').zfill(int(block_size / 4)))
    print('ciphertext: ', hex(plain2)[2:].rstrip('L').zfill(int(block_size / 4)))
    print('plaintext2: ', hex(cipher)[2:].rstrip('L').zfill(int(block_size / 4)))
    print('\n')


# 32 64
block_size32, key_size32, master_key32, plaintext32 = 32, 64, 0x1918111009080100, 0x65656877
simeck32 = Simeck(block_size32, key_size32, master_key32)
ciphertext32 = simeck32.encrypt(plaintext32)
plaintext32_de = simeck32.decrypt(ciphertext32)
print_test_vector(block_size32, key_size32, master_key32, plaintext32, ciphertext32, plaintext32_de)

# 48 96
block_size48, key_size48, master_key48, plaintext48 = 48, 96, 0x1a19181211100a0908020100, 0x72696320646e
simeck48 = Simeck(block_size48, key_size48, master_key48)
ciphertext48 = simeck48.encrypt(plaintext48)
plaintext48_de = simeck48.decrypt(ciphertext48)
print_test_vector(block_size48, key_size48, master_key48, plaintext48, ciphertext48, plaintext48_de)

# 96 128
block_size64, key_size64, master_key64, plaintext64 = 64, 128, 0x1b1a1918131211100b0a090803020100, 0x656b696c20646e75
simeck64 = Simeck(block_size64, key_size64, master_key64)
ciphertext64 = simeck64.encrypt(plaintext64)
plaintext64_de = simeck64.decrypt(ciphertext64)
print_test_vector(block_size64, key_size64, master_key64, plaintext64, ciphertext64, plaintext64_de)
