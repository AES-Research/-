import binascii


# 定义最佳线性逼近式
best_linear_approximations = {
    1: {(16, 15): -18},
    2: {(34, 11): -16, (34, 15): 16},
    3: {(34, 15): 16},
    4: {(34, 15): -16, (40, 15): -16, (43, 9): -16},
    5: {(16, 15): -20},
    6: {(16, 7): -14},
    7: {(59, 4): -18},
    8: {(16, 15): -16}
}

# 构建线性近似表
def build_LAT(best_linear_approximations):
    LAT = {i: {} for i in range(1, 9)}  # 初始化LAT字典，包含8个S盒
    for S, approximations in best_linear_approximations.items():
        for (alpha, beta), NS in approximations.items():
            LAT[S].setdefault(alpha, {})[beta] = NS
    return LAT

# 打印线性近似表
def print_LAT(LAT):
    for S, approximations in LAT.items():
        print(f"S盒{S}的线性近似表:")
        for alpha, betas in approximations.items():
            for beta, NS in betas.items():
                print(f"\tα={bin(alpha)[2:].zfill(6)}, β={bin(beta)[2:].zfill(4)}, NS={NS}")
        print()

# 获取并打印线性近似表
LAT = build_LAT(best_linear_approximations)
print_LAT(LAT)

# 将十六进制字符串转换为字节串
def hex_to_bytes(hex_str):
    return binascii.unhexlify(hex_str)

# 假设我们有足够的已知明文-密文对
known_plaintexts_hex = [
    'aaaec75c9fa73091', 'c691a8ad944303c2', 'c09c6b1e91cf8cb4', 'd46b4860bcc80f44', '8b9d130791b7e0dd',
    '9f1515d7b66927fd', '829716b707b58618', 'd3fe23dd8a0f53b1', 'b7182f897e057271', '532540e593021f72'
]
known_ciphertexts_hex = [
    '966e0ce6fccb9f35', 'dae61fab659da46f', 'fd62cd090a62b115', 'eefd576e63c539cf', '3f80417c1ef81936',
    '4756f4ccde6803c0', '59a6476ddd33ba1c', '54d7889640f33f31', '73f830d1ac4f3ce5', '4e62334cf483cd4e'
]

# 将十六进制字符串转换为字节串
known_plaintexts = [hex_to_bytes(pt) for pt in known_plaintexts_hex]
known_ciphertexts = [hex_to_bytes(ct) for ct in known_ciphertexts_hex]

# 计算线性逼近方程的左侧值
def calculate_linear_approximation_left_side(pt, ct, S, alpha, beta):
    """
    计算线性逼近方程的左侧值，根据给定的线性逼近式逻辑来实现。
    :param pt: 明文字节串
    :param ct: 密文字节串
    :param S: S盒编号（1 - 8）
    :param alpha: alpha值
    :param beta: beta值
    :return: 线性逼近方程左侧计算结果
    """
    # 提取与当前S盒相关的比特，先转换为整数方便后续按位操作
    pt_int = int.from_bytes(pt, 'big')
    ct_int = int.from_bytes(ct, 'big')
    left_side = 0
    if S == 1:
        left_side = (
            ((pt_int >> 31) & 1) ^ ((ct_int >> 31) & 1) ^
            (((pt_int >> 23) & 1) ^ ((pt_int >> 15) & 1) ^ ((pt_int >> 9) & 1) ^ ((pt_int >> 1) & 1)) ^
            (((ct_int >> 23) & 1) ^ ((ct_int >> 15) & 1) ^ ((ct_int >> 9) & 1) ^ ((ct_int >> 1) & 1))
        )
    elif S == 2:
        left_side = (
            (((pt_int >> 28) & 1) ^ ((pt_int >> 24) & 1)) ^
            (((ct_int >> 28) & 1) ^ ((ct_int >> 24) & 1)) ^
            (((pt_int >> 19) & 1) ^ ((pt_int >> 30) & 1) ^ ((pt_int >> 14) & 1)) ^
            (((ct_int >> 19) & 1) ^ ((ct_int >> 30) & 1) ^ ((ct_int >> 14) & 1))
        )
    elif S == 3:
        left_side = (
            (((pt_int >> 24) & 1) ^ ((pt_int >> 20) & 1)) ^
            (((ct_int >> 24) & 1) ^ ((ct_int >> 20) & 1)) ^
            (((pt_int >> 8) & 1) ^ ((pt_int >> 16) & 1) ^ ((pt_int >> 2) & 1) ^ ((pt_int >> 26) & 1)) ^
            (((ct_int >> 8) & 1) ^ ((ct_int >> 16) & 1) ^ ((ct_int >> 2) & 1) ^ ((ct_int >> 26) & 1))
        )
    elif S == 4:
        if alpha == 34 and beta == 15:
            left_side = (
                (((pt_int >> 20) & 1) ^ ((pt_int >> 16) & 1)) ^
                (((ct_int >> 20) & 1) ^ ((ct_int >> 16) & 1)) ^
                (((pt_int >> 6) & 1) ^ ((pt_int >> 12) & 1) ^ ((pt_int >> 22) & 1) ^ ((pt_int >> 31) & 1)) ^
                (((ct_int >> 6) & 1) ^ ((ct_int >> 12) & 1) ^ ((ct_int >> 22) & 1) ^ ((ct_int >> 31) & 1))
            )
        elif alpha == 40 and beta == 15:
            left_side = (
                (((pt_int >> 20) & 1) ^ ((pt_int >> 18) & 1)) ^
                (((ct_int >> 20) & 1) ^ ((ct_int >> 18) & 1)) ^
                (((pt_int >> 6) & 1) ^ ((pt_int >> 12) & 1) ^ ((pt_int >> 22) & 1) ^ ((pt_int >> 31) & 1)) ^
                (((ct_int >> 6) & 1) ^ ((ct_int >> 12) & 1) ^ ((ct_int >> 22) & 1) ^ ((ct_int >> 31) & 1))
            )
        elif alpha == 43 and beta == 9:
            left_side = (
                (((pt_int >> 20) & 1) ^ ((pt_int >> 18) & 1) ^ ((pt_int >> 16) & 1) ^ ((pt_int >> 15) & 1)) ^
                (((ct_int >> 20) & 1) ^ ((ct_int >> 18) & 1) ^ ((ct_int >> 16) & 1) ^ ((ct_int >> 15) & 1)) ^
                (((pt_int >> 6) & 1) ^ ((pt_int >> 31) & 1)) ^
                (((ct_int >> 6) & 1) ^ ((ct_int >> 31) & 1))
            )
    elif S == 5:
        left_side = (
            ((pt_int >> 15) & 1) ^ ((ct_int >> 15) & 1) ^
            (((pt_int >> 24) & 1) ^ ((pt_int >> 18) & 1) ^ ((pt_int >> 7) & 1) ^ ((pt_int >> 29) & 1)) ^
            (((ct_int >> 24) & 1) ^ ((ct_int >> 18) & 1) ^ ((ct_int >> 7) & 1) ^ ((ct_int >> 29) & 1))
        )
    elif S == 6:
        left_side = (
            ((pt_int >> 11) & 1) ^ ((ct_int >> 11) & 1) ^
            (((pt_int >> 3) & 1) ^ ((pt_int >> 21) & 1) ^ ((pt_int >> 13) & 1)) ^
            (((ct_int >> 3) & 1) ^ ((ct_int >> 21) & 1) ^ ((ct_int >> 13) & 1))
        )
    elif S == 7:
        left_side = (
            (((pt_int >> 8) & 1) ^ ((pt_int >> 7) & 1) ^ ((pt_int >> 6) & 1) ^ ((pt_int >> 4) & 1) ^ ((pt_int >> 3) & 1)) ^
            (((ct_int >> 8) & 1) ^ ((ct_int >> 7) & 1) ^ ((ct_int >> 6) & 1) ^ ((ct_int >> 4) & 1) ^ ((ct_int >> 3) & 1)) ^
            (((pt_int >> 20) & 1)) ^
            (((ct_int >> 20) & 1))
        )
    elif S == 8:
        left_side = (
            ((pt_int >> 3) & 1) ^ ((ct_int >> 3) & 1) ^
            (((pt_int >> 27) & 1) ^ ((pt_int >> 5) & 1) ^ ((pt_int >> 17) & 1) ^ ((pt_int >> 11) & 1)) ^
            (((ct_int >> 27) & 1) ^ ((ct_int >> 5) & 1) ^ ((ct_int >> 17) & 1) ^ ((ct_int >> 11) & 1))
        )
    return left_side

# 计算线性逼近方程的右侧值
def calculate_linear_approximation_right_side(key, S, alpha, beta):
    """
    计算线性逼近方程的右侧值，根据给定的线性逼近式逻辑来实现，接收alpha和beta参数。
    :param key: 密钥
    :param S: S盒编号（1 - 8）
    :param alpha: alpha值
    :param beta: beta值
    :return: 线性逼近方程右侧计算结果
    """
    right_side = 0
    if S == 1:
        right_side = ((key >> 46) & 1) ^ ((key >> 46) & 1)
    elif S == 2:
        if alpha == 34 and beta == 11:
            right_side = ((key >> 41) & 1) ^ ((key >> 37) & 1)
        elif alpha == 34 and beta == 15:
            right_side = ((key >> 41) & 1) ^ ((key >> 37) & 1)
    elif S == 3:
        right_side = ((key >> 35) & 1) ^ ((key >> 31) & 1)
    elif S == 4:
        if alpha == 34 and beta == 15:
            right_side = ((key >> 29) & 1) ^ ((key >> 25) & 1)
        elif alpha == 40 and beta == 15:
            right_side = ((key >> 29) & 1) ^ ((key >> 27) & 1)
        elif alpha == 43 and beta == 9:
            right_side = ((key >> 29) & 1) ^ ((key >> 27) & 1) ^ ((key >> 25) & 1) ^ ((key >> 24) & 1)
    elif S == 5:
        right_side = ((key >> 22) & 1) ^ ((key >> 22) & 1)
    elif S == 6:
        right_side = ((key >> 16) & 1) ^ ((key >> 16) & 1)
    elif S == 7:
        right_side = ((key >> 11) & 1) ^ ((key >> 10) & 1) ^ ((key >> 9) & 1) ^ ((key >> 7) & 1) ^ ((key >> 6) & 1)
    elif S == 8:
        right_side = ((key >> 4) & 1) ^ ((key >> 4) & 1)
    return right_side



# 定义一个函数来计算给定密钥候选的得分
def calculate_key_score(key, LAT, known_pt, known_ct):
    score = 0
    for pt, ct in zip(known_pt, known_ct):
        for S, approximations in LAT.items():  # 遍历每个S盒
            for alpha, betas in approximations.items():
                for beta, NS in betas.items():
                    # 计算线性逼近方程的左侧和右侧，添加alpha和beta作为参数传递
                    left_side = calculate_linear_approximation_left_side(pt, ct, S, alpha, beta)
                    right_side = calculate_linear_approximation_right_side(key, S, alpha, beta)

                    if (left_side == 0 and NS < 0) or (left_side!= 0 and NS > 0):
                        score += abs(NS)  # 使用偏差值的绝对值作为权重
                    else:
                        score -= abs(NS)
    return score

# 对的密钥候选进行评分
def find_best_key_reduced(LAT, known_pt, known_ct):
    best_key = 0
    best_score = -float('inf')
    for key in range(2 ** 16):  # 只遍历前16位密钥
        score = calculate_key_score(key << 40, LAT, known_pt, known_ct)  # 假设其余40位为0
        if score > best_score:
            best_score = score
            best_key = key
    return best_key, best_score

# 获取并打印最佳密钥候选
best_key, best_score = find_best_key_reduced(LAT, known_plaintexts, known_ciphertexts)
print(f"最佳密钥候选的前16位: {best_key:016b}, 得分: {best_score}")