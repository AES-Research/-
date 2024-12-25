# -*- coding: gb2312 -*-
def int2bin(x: int, length):
    """
    将整数转换为指定长度的二进制列表
    输入: x (int) - 要转换的整数
          length (int) - 二进制表示的长度
    输出: list - 包含二进制位（0或1）的列表
    """
    b = format(x, '0{}b'.format(length))  # 将整数x格式化为指定长度的二进制字符串
    b = [int(i) for i in b]  # 将二进制字符串转换为包含二进制位的列表
    return b


def bin2int(b: list):
    """
    将二进制列表转换为整数
    输入: b (list) - 包含二进制位（0或1）的列表
    输出: int - 对应的整数
    """
    x = [str(i) for i in b]  # 将二进制列表转换为二进制字符串
    x = int(''.join(x), 2)  # 将二进制字符串转换为整数
    return x


def int2hex(x: int, length):
    """
    将整数转换为指定长度的十六进制字符串
    输入: x (int) - 要转换的整数
        length (int) - 十六进制表示的长度
    输出: str - 十六进制字符串
    """
    h = format(x, '0{}x'.format(length))  # 将整数x格式化为指定长度的十六进制字符串
    return h


def hex2int(h: str):
    """
    将十六进制字符串转换为整数
    输入: h (str) - 十六进制字符串
    输出: int - 对应的整数
    """
    return int(h, 16)  # 将十六进制字符串转换为整数


def hex2bin(h: str, length):
    """
    将十六进制字符串转换为指定长度的二进制列表
    输入: h (str) - 十六进制字符串
         length (int) - 二进制表示的长度
    输出: list - 包含二进制位（0或1）的列表
    """
    b = format(int(h, 16), '0{}b'.format(length))  # 将十六进制字符串转换为整数，再转换为指定长度的二进制字符串
    b = [int(i) for i in b]  # 将二进制字符串转换为包含二进制位的列表
    return b


def bin2hex(b: list, length):
    """
    将二进制列表转换为指定长度的十六进制字符串
    输入: b (list) - 包含二进制位（0或1）的列表
         length (int) - 十六进制表示的长度
    输出: str - 十六进制字符串
    """
    b = [str(i) for i in b]  # 将二进制列表转换为二进制字符串
    h = format(int(''.join(b), 2), '0{}x'.format(length))  # 将二进制字符串转换为整数，再转换为指定长度的十六进制字符串
    return h


def xor(a, b):
    """
    对两个等长的列表进行逐位异或运算
    输入: a (list) - 第一个列表（包含整数，通常用于表示二进制位）
         b (list) - 第二个列表（与a等长，包含整数，通常用于表示二进制位）
    输出: list - 逐位异或运算后的结果列表
    """
    assert len(a) == len(b)  # 确保两个列表等长
    c = [i ^ j for i, j in zip(a, b)]  # 对两个列表进行逐位异或运算
    return c