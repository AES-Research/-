from des import Des, P_Table, PC2_Table, LOOP_Table, PC1_Table
import random
import numpy as np
from collections import defaultdict
import copy
from utils import bin2int, bin2hex, int2bin, int2hex, hex2bin, hex2int, xor
import itertools as it
import time
import tqdm
import datetime

class DifferentialCryptandysis:
    def __init__(self, des: Des, M, testnum=8) -> None:
        """
        初始化差分密码分析类
        :param des: Des类的实例，表示DES加密算法
        :param M: 进行差分分析的次数
        :param testnum: 测试时使用的明文对数，用于提高攻击精度
        """
        # testnum: 最终测试时，用于测试的次数，可以提高攻击的精度
        self.des = des  # DES加密算法实例
        self.N = des.N  # DES加密的轮数
        self.testnum = testnum 
        self.STable = self.Sxor()  # 预先计算的S盒差分表
        self.prob_key = [[] for _ in range(8)]  # 存储每个S盒可能的密钥差分
        self.M = M # 使用M次差分分析

        # PC2_Table和PC1_Table中未使用的位置，用于密钥恢复
        self.position1 = sorted([k for k in range(1, 57) if k not in PC2_Table]) # PC2_Table中丢失的位置
        self.position2 = sorted([k for k in range(1, 65) if k not in PC1_Table]) # 校验和的位置

        # 生成测试明文对
        self.__D = Des(self.N)
        self.__P = [bin2hex([random.randint(0, 1) for _ in range(64)], 16) for _ in range(self.testnum)]
        self.__T = [self.des.encode(p) for p in self.__P]  # 加密后的测试明文对
        self.__K = None  # 最终恢复的密钥
 
        self.pbar = None  # 进度条对象

    def Sxor(self):  
        """
        预先计算S盒的差分表
        :return: 一个三维列表，表示每个S盒在不同输入差分和输出差分下的可能输入值
        """
        Sxor = [[[[] for _ in range(16)] for _ in range(64)] for _ in range(8)]
        for i in range(8):  # 对于每个S盒
            for B in range(64):  # 遍历所有可能的6位输入
                for BB in range(64):  # 遍历所有可能的6位输入作为差分
                    inxor = B ^ BB  # 输入差分
                    outxor = bin2int(self.des.Sx(int2bin(B, 6), i)) ^ bin2int(self.des.Sx(int2bin(BB, 6), i))  # 输出差分
                    Sxor[i][inxor][outxor].append(B)  # 将输入B添加到对应差分表的列表中
        return Sxor

    def analyze(self) -> str:
        """
        执行差分密码分析
        :return: 恢复的密钥（以十六进制字符串形式）
        """
        print('【Start analysing key...】')
        for _ in tqdm.trange(self.M):  # 执行M次差分分析
            self.analyze_single()
        key = self.find_key()  # 找到可能的48位密钥
        print('【Find the 48bit keys, start a search for the initial key...】')
        self.pbar = tqdm.trange(2**len(self.position1))  # 初始化进度条
        if not self.key_reverse(key):  # 尝试恢复64位初始密钥
            print('Analyze fail!')
            exit(0)
        return self.__K
 
    def analyze_single(self):
        """
        执行一次差分分析
        :return: 无返回值，但会更新prob_key列表，存储每个S盒可能的密钥差分
        """
        # 生成一对随机明文P和PP，并计算其经过F函数后的输出
        P, PP = self.generateP()
        L0, R0 = copy.deepcopy(P[0:32]), copy.deepcopy(P[32:64])  # 左半部分和右半部分
        LL0, RR0 = copy.deepcopy(PP[0:32]), copy.deepcopy(PP[32:64])
        L1, R1 = self.des.F(L0, R0)  # 明文P的F函数输出
        LL1, RR1 = self.des.F(LL0, RR0)  # 明文PP的F函数输出
 
        # 计算E扩展后的输入差分和输出差分
        E = self.des.E(L1)
        EE = self.des.E(LL1)
        IN = xor(E, EE)  # 输入差分
 
        dR1 = xor(R1, RR1)  # 输出差分（右半部分）
        OUT = list(np.array(dR1)[np.argsort(P_Table)])  # 根据P_Table重新排序输出差分
 
        # 遍历每个S盒，更新prob_key列表
        Ex = [bin2int(E[i*6:(i+1)*6]) for i in range(8)]  # E扩展后的每6位一组
        for i in range(8):  # 对于每个S盒
            INx = bin2int(IN[i*6:(i+1)*6])  # 输入差分
            OUTx = bin2int(OUT[i*4:(i+1)*4])  # 输出差分
            for B in self.STable[i][INx][OUTx]:  # 遍历S盒差分表中对应的输入值
                K = B ^ Ex[i]  # 计算可能的密钥差分
                self.prob_key[i].append(K)  # 添加到prob_key列表中
  
    def get_initial_key(self, key) -> bool:
        """
        尝试通过差分密码分析找到初始密钥。
        
        输入:
        key: list，48位的二进制密钥（假设已根据PC1表选择）
        
        输出:
        bool，如果找到正确的密钥则返回True，否则返回False
        """
        # 将48位密钥通过PC2表扩展到56位，并插入位置1的0
        # 根据LOOP表和位置1，生成所有可能的密钥排列组合
        # 对于每种组合，通过PC1表扩展到64位，并插入位置2的0，然后进行位移和S盒替换（此处通过__D.set_key(key_)模拟）
        # 检查是否满足差分密码分析的特定条件（即P和T的特定关系）
        # 如果找到满足条件的密钥，返回True并保存密钥

        key = list(np.array(key)[np.argsort(PC2_Table)])
        for p in self.position1: key.insert(p-1, 0) # 56bit
        offset = sum(LOOP_Table[0:self.N])
        combinations = list(it.product([0, 1], repeat=len(self.position1)))
        for comb in combinations:
            key_ = np.array(key)
            key_[np.array(self.position1)-1] = comb
            key_ = list(key_)
            t1 = key_[0:28-offset]
            t0 = key_[28-offset:28]
            t3 = key_[28:56-offset]
            t2 = key_[56-offset:56]
            key_ = t0 + t1 + t2 + t3 # 56bit
            # 56bit -> 64bit
            key_ = list(np.array(key_)[np.argsort(PC1_Table)])
            for i in self.position2:
                key_.insert(i-1, 0)
            for j in range(7):
                key_[i-1] ^= key_[i-j-2]
            key_ = bin2hex(key_, 16)
      
            OK = True
            self.__D.set_key(key_)
            for __P, __T in zip(self.__P, self.__T):
                T = self.__D.encode(__P)
                P = self.__D.decode(__T)
                if __T != T and __P != P:
                    OK = False
                    break
            if OK:
                self.__K = key_
                self.pbar.close()
                return True
            self.pbar.update(1)
        self.pbar.close()
        return False

    def key_reverse(self, key): # 48bit -> 56bit -> 64bit
        key = hex2bin(key, 48)
        return self.get_initial_key(key)

    def find_key(self):
        """
        基于概率分析找到可能的密钥。
        
        输出:
        str，预测的16进制密钥
        """
        # 遍历每个字节的概率分布，找到最可能的字节组合
        # 将这些字节组合成一个完整的64位（实际使用48位有效密钥）密钥
        # 返回预测的16进制密钥
        key_map = [defaultdict(int) for _ in range(8)]
        key = []
        for i in range(8):
            pk = self.prob_key[i]
            for k in pk:
                key_map[i][k] += 1
            m = max(key_map[i].values())
            temp = [k for k, v in key_map[i].items() if v == m]
            if len(temp) != 1:
                print('Try again!')
                exit(0)
            key.extend(int2bin(temp[0], 6))
        key = bin2hex(key, 16)
        return key
    
    def generateP(self):
        """
        生成一对随机明文P和PP（PP是P的右半部分随机化后的明文）
        :return: 返回一对明文P和PP（均为十六进制字符串形式）
        """
        P = [random.randint(0,1) for _ in range(64)]
        PP = copy.deepcopy(P[0:32]) + [random.randint(0,1) for _ in range(32)]
        return P, PP


if __name__ == '__main__':
    round = 1
    des = Des(round)
    # des.set_key('f93fde5a749fe21b')
    print('\nDifferential Cryptandysis of {}-round DES'.format(round))
    print('\n【Built a Des!】')
    dc = DifferentialCryptandysis(des, 5, 10)
    start = time.time()
    key = dc.analyze()
    end = time.time()
    during = datetime.timedelta(seconds=end-start)
    print('【Finish analysing, it spends {}】'.format(during))

    N = 1000
    print('\nOriginal key informations:')
    des.get_key()
    print('\nThe predicted key is {}, testing {} random plaintext...'.format(key, N))
    d = Des(round)
    d.set_key(key)
    for i in tqdm.trange(N):
        plaintext = bin2hex([random.randint(0, 1) for _ in range(64)], 16)
        ciphertext_gt = des.encode(plaintext) # groundtrue
        ciphertext_pre = d.encode(plaintext) # predict
        plaintext_pre = d.decode(ciphertext_gt)
        if ciphertext_gt != ciphertext_pre or plaintext != plaintext_pre:
            print('\nAttack unsuccessfully!')
            exit(0)
    print('\nAll test pass. Attack successfully! O.o')
