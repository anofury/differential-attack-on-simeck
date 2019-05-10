# 不同加密模式对应的轮数
NUM_ROUNDS = {
    # (block_size, key_size): num_rounds
    # (2n, 4n): n ∈ {16,24,32}
    (32, 64): 32,
    (48, 96): 36,
    (64, 128): 44,
}

# 用来存放破解出来的最后一轮密钥
attack_key_result = []


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


class BitFlipToSimeck:
    def __init__(self, block_size, key_size, plaintext, master_key, ciphertext_ori, attack_round):
        assert (block_size, key_size) in NUM_ROUNDS
        assert 0 <= master_key < (1 << key_size)
        self._block_size = block_size
        self._key_size = key_size
        self._plaintext = plaintext
        self._attack_round = attack_round
        self._ciphertext_ori = ciphertext_ori
        self._word_size = int(block_size / 2)  # 明文的一半位数，分为左和右
        self._num_rounds = NUM_ROUNDS[(block_size, key_size)]  # 轮数
        self._sequence = get_sequence(self._num_rounds)  # m-序列
        self._modulus = 1 << self._word_size  # 明文位数一半的值，系数
        self._round_keys = self._change_key(master_key)
        self._encrypt()
        self._cal_last_round_key()

    # 循环移位
    def _LROT(self, x, r):
        assert 0 <= x < self._modulus
        res = (x << r) % self._modulus
        res |= x >> (self._word_size - r)
        return res

    # left right 轮函数f 轮密钥 做计算
    def _round(self, round_key, left, right, round_time):
        assert 0 <= round_key < self._modulus
        assert 0 <= left < self._modulus
        assert 0 <= right < self._modulus

        # 在加密过程中的倒数第二轮注入故障
        if round_time == self._num_rounds - 2:
            left ^= 2 ** self._attack_round

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
            left, right = self._round(constant ^ self._sequence[i], left, right, -1)
            states.append(left)
            states.pop(0)
            states[0] = right
        return round_keys

    # 加密函数
    def _encrypt(self):
        assert 0 <= self._plaintext < (1 << self._block_size)
        left = self._plaintext >> self._word_size
        right = self._plaintext % self._modulus

        for idx in range(self._num_rounds):
            left, right = self._round(self._round_keys[idx], left, right, idx)

        ciphertext = (left << self._word_size) | right
        self._ciphertext = ciphertext

        # 输出最后一轮密钥
        if self._attack_round == 0:
            print("right_last_round_key: ", "0x" + list(map(lambda x: hex(x)[2:], self._round_keys))[-1])

    # 根据故障攻击计算出最后一轮密钥方法
    def _cal_last_round_key(self):
        bin_ciphertext_ori = list(map(lambda x: int(x), list(bin(self._ciphertext_ori)[2:].zfill(self._block_size))))
        bin_ciphertext = list(map(lambda x: int(x), list(bin(self._ciphertext)[2:].zfill(self._block_size))))
        xT, yT = bin_ciphertext_ori[:int(len(bin_ciphertext_ori) / 2)], bin_ciphertext_ori[
                                                                        int(len(bin_ciphertext_ori) / 2):]
        x_T, y_T = bin_ciphertext[:int(len(bin_ciphertext) / 2)], bin_ciphertext[int(len(bin_ciphertext) / 2):]

        result_bit1 = self._word_size - (self._attack_round - 5) % self._word_size - 1
        result_bit1_5 = self._word_size - (self._attack_round - 10) % self._word_size - 1
        result_bit1_1 = self._word_size - (self._attack_round - 6) % self._word_size - 1

        result_bit2 = self._word_size - (self._attack_round + 5) % self._word_size - 1
        result_bit2_5 = self._word_size - (self._attack_round) % self._word_size - 1
        result_bit2_1 = self._word_size - (self._attack_round + 4) % self._word_size - 1

        yTj = yT[self._word_size - self._attack_round - 1]
        y_Tj = y_T[self._word_size - self._attack_round - 1]

        yTj_5 = yT[self._word_size - self._attack_round - 6]
        y_Tj_5 = y_T[self._word_size - self._attack_round - 6]

        attack_key_result[result_bit1] = (yTj ^ y_Tj) ^ (yT[result_bit1] & yT[result_bit1_5] ^ yT[result_bit1_1]) ^ xT[
            result_bit1]
        attack_key_result[result_bit2] = (yTj_5 ^ y_Tj_5) ^ (yT[result_bit2] & yT[result_bit2_5] ^ yT[result_bit2_1]) ^ \
                                         xT[result_bit2]


if __name__ == '__main__':
    block_size, key_size, plaintext, key, ciphertext_ori = 32, 64, 0x65656877, 0x1918111009080100, 0x770d2c76
    # block_size, key_size, plaintext, key, ciphertext_ori = 48, 96, 0x72696320646e, 0x1a19181211100a0908020100, 0xf3cf25e33b36
    # block_size, key_size, plaintext, key, ciphertext_ori = 64, 128, 0x656b696c20646e75, 0x1b1a1918131211100b0a090803020100, 0x45ce69025f7ab7ed

    # 开始攻击
    n = int(block_size / 2)
    attack_key_result = [0] * n
    attack_times = (n - 10) if n > 20 else 10
    for i in range(attack_times):
        BitFlipToSimeck(block_size, key_size, plaintext, key, ciphertext_ori, i)

    # 输出通过故障攻击得出来的最后一轮密钥
    print(" hack_last_round_key: ", hex(int(''.join(map(lambda x: str(x), attack_key_result)), 2)))

# 测试样例
#     plaintext32: 0x65656877
#           key64: 0x1918111009080100
#    ciphertext32: 0x770d2c76
# last _round_key: 0x7fbe

#     plaintext48: 0x72696320646e
#           key96: 0x1a19181211100a0908020100
#    ciphertext48: 0xf3cf25e33b36
# last _round_key: 0xda7a12

#     plaintext64: 0x656b696c20646e75
#          key128: 0x1b1a1918131211100b0a090803020100
#    ciphertext64: 0x45ce69025f7ab7ed
# last _round_key: 0x3d5eab8f
