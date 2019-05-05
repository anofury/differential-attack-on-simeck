
# 不同加密模式对应的轮数
NUM_ROUNDS = {
    # (block_size, key_size): num_rounds
    # (2n, 4n): n ∈ {16,24,32}
    (32, 64): 32,
    (48, 96): 36,
    (64, 128): 44,
}


# LFSR 生成的 m-序列
def get_sequence(num_rounds):
    if num_rounds < 40:
        states = [1] * 5
    else:
        states = [1] * 6

    for i in range(num_rounds - 5):
        if num_rounds < 40:
            feedback = states[i + 2] ^ states[i]
        else:
            feedback = states[i + 1] ^ states[i]
        states.append(feedback)

    return tuple(states)


class Simeck:
    def __init__(self, block_size, key_size, master_key):
        assert (block_size, key_size) in NUM_ROUNDS
        assert 0 <= master_key < (1 << key_size)
        self._block_size = block_size
        self._key_size = key_size
        self._word_size = int(block_size / 2)  # 明文的一半位数，分为左和右
        self._num_rounds = NUM_ROUNDS[(block_size, key_size)]  # 轮数
        self._sequence = get_sequence(self._num_rounds)  # m-序列
        self._modulus = 1 << self._word_size  # 明文位数一半的值，系数
        self._change_key(master_key)

    # 循环移位
    def _LROT(self, x, r):
        assert 0 <= x < self._modulus
        res = (x << r) % self._modulus
        res |= x >> (self._word_size - r)
        return res

    # left right 轮函数f 轮密钥 做计算
    # decrypt: [True, False] 是否为解密过程
    def _round(self, round_key, left, right, decrypt):
        assert 0 <= round_key < self._modulus
        assert 0 <= left < self._modulus
        assert 0 <= right < self._modulus
        if decrypt:  # 解密过程
            temp = right
            right = left ^ (right & self._LROT(right, 5)) ^ self._LROT(right, 1) ^ round_key
            left = temp
        else:  # 加密过程
            temp = left
            left = right ^ (left & self._LROT(left, 5)) ^ self._LROT(left, 1) ^ round_key
            right = temp
        return left, right

    # 密钥扩展函数
    def _change_key(self, master_key):
        assert 0 <= master_key < (1 << self._key_size)
        states = []  # 密钥寄存器
        # 初始状态
        for i in range(int(self._key_size / self._word_size)):
            states.append(master_key % self._modulus)
            master_key >>= self._word_size

        constant = self._modulus - 4  # 常量 C = 2^n-4
        round_keys = []
        for i in range(self._num_rounds):
            round_keys.append(states[0])
            left, right = states[1], states[0]
            left, right = self._round(constant ^ self._sequence[i], left, right, False)
            states.append(left)
            states.pop(0)
            states[0] = right

        self.__round_keys = tuple(round_keys)

    # 加密函数
    def encrypt(self, plaintext):
        assert 0 <= plaintext < (1 << self._block_size)
        left = plaintext >> self._word_size
        right = plaintext % self._modulus

        for idx in range(self._num_rounds):
            left, right = self._round(self.__round_keys[idx], left, right, False)

        ciphertext = (left << self._word_size) | right
        return ciphertext

    # 解密函数
    def decrypt(self, ciphertext):
        assert 0 <= ciphertext < (1 << self._block_size)
        left = ciphertext >> self._word_size
        right = ciphertext % self._modulus

        for idx in range(self._num_rounds - 1, -1, -1):
            left, right = self._round(self.__round_keys[idx], left, right, True)

        plaintext = (left << self._word_size) | right
        return plaintext


# 将10进制转换成16进制输出
def print_test_vector(block_size, key_size, key, plain, cipher):
    print('Simeck: ', block_size, key_size)
    print('key   : ', hex(key)[2:].rstrip('L').zfill(int(key_size / 4)))
    print('text1 : ', hex(plain)[2:].rstrip('L').zfill(int(block_size / 4)))
    print('text2 : ', hex(cipher)[2:].rstrip('L').zfill(int(block_size / 4)))
    print('\n')


# 测试
def main():
    plaintext32_en = 0x65656877
    ciphertext32_de = 0x770d2c76
    key64 = 0x1918111009080100
    simeck32 = Simeck(32, 64, key64)
    ciphertext32_en = simeck32.encrypt(plaintext32_en)
    plaintext32_de = simeck32.decrypt(ciphertext32_de)

    print_test_vector(32, 64, key64, plaintext32_en, ciphertext32_en)
    print_test_vector(32, 64, key64, ciphertext32_de, plaintext32_de)


if __name__ == '__main__':
    main()
