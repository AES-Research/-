# 三轮DES差分攻击实现

## DES 加密算法概述

DES 是一种对称加密算法，它使用 56 位密钥对 64 位的数据块进行加密和解密操作。加密过程包括初始置换、16 轮的 Feistel 结构迭代以及最终置换。在每一轮中，数据的右半部分通过一个扩展置换（E 扩展）后与子密钥进行异或操作，然后经过 S 盒替换和 P 置换，最后与左半部分进行异或得到新的右半部分，而原来的右半部分成为新的左半部分，如此反复 16 轮。

DES 的安全性依赖于其密钥的保密性和复杂的加密结构，但随着计算能力的提升和密码分析技术的发展，其 56 位的密钥长度逐渐显示出安全性上的不足。

## 差分攻击原理

差分攻击是一种针对对称加密算法的密码分析方法，其核心思想是通过分析明文对的差分在加密过程中的传播特性，来推断加密密钥的信息。

具体来说，攻击者选择具有特定差分（即两个明文之间的差异）的明文对，对这些明文对进行加密，并观察密文对的差分。由于加密算法的结构特点，明文对的差分在经过加密轮数的变换后，会呈现出一定的规律。通过大量的明文对差分分析，攻击者可以利用这些规律来确定加密过程中某些中间值的可能情况，进而推导出密钥的相关信息。

在针对 DES 的差分攻击中，重点关注的是 S 盒的输入输出差分特性。由于 S 盒是 DES 中唯一的非线性组件，其对差分的变换相对复杂且具有一定的规律。攻击者通过预先计算 S 盒在不同输入差分下可能产生的输出差分以及对应的输入值，构建差分表（在代码中为 `Sxor` 函数所计算的表）。然后，在实际的差分分析过程中，根据明文对加密后的密文差分，结合差分表来推断每个 S 盒可能的密钥差分，经过多次分析和统计，最终确定最有可能的密钥值。

## 实现思想

1. **初始化阶段**
   - 传入 DES 加密实例、分析次数`M`与测试明文对数`testnum`，初始化差分密码分析类。保存 DES 相关参数，如轮数`N` ，预计算 S 盒的差分表`Sxor`，并生成用于测试的明文对及其密文。同时初始化存储每个 S 盒可能密钥差分的`prob_key`列表，记录 PC1、PC2 表未使用的位置，用于后续密钥恢复。
2. **核心差分分析过程**
   - 单次分析 (`analyze_single`)
     - 随机生成一对明文`P`和`PP`，将它们分割成左右两部分，分别经过 DES 的`F`函数得到输出。
     - 计算`F`函数输入的扩展差分`IN`与输出的右半部分差分`dR1`，并对`dR1`按`P_Table`排序得到`OUT`。
     - 把扩展后的输入按每 6 位一组拆分，针对每个 S 盒，依据输入差分`INx`、输出差分`OUTx`去查预计算的 S 盒差分表`STable`，得到对应的输入值，由此算出可能的密钥差分，更新`prob_key`。
   - **多次分析 (`analyze`)**：重复执行`M`次单次分析，积累足够多的密钥差分信息。
3. **密钥推导阶段**
   - **寻找可能的 48 位密钥 (`find_key`)**：遍历`prob_key`中每个 S 盒对应的密钥差分统计信息，找出出现频率最高的字节组合，拼接成一个 16 进制的 48 位密钥。
   - **恢复初始 64 位密钥 (`key_reverse`与`get_initial_key`)**：先将 48 位密钥扩展到 56 位，再穷举 PC1 表未使用位置的所有可能组合，进一步扩展到 64 位，逐一测试这些组合，若某个组合能满足特定的明文密文对应关系，就认定其为初始密钥。
4. **验证阶段**：使用恢复出的密钥进行大量随机明文加密测试，若加密解密结果与原始 DES 加密结果一致，则判定攻击成功。

## 依赖库

- `des`：自定义的 DES 加密算法实现库，包含`Des`类以及相关的置换表（如`P_Table`、`PC2_Table`、`LOOP_Table`、`PC1_Table`）和 S 盒变换函数（`Sx`）。
- `numpy`：用于数值计算，主要在数组操作和排序方面发挥作用。
- `collections`中的`defaultdict`：方便对每个 S 盒的密钥差分进行计数统计。
- `copy`：用于深拷贝明文数据，确保在生成明文对和分析过程中数据的独立性。
- `utils`：自定义的工具库，提供了二进制与十六进制、整数之间的转换函数（`bin2int`、`bin2hex`、`int2bin`、`int2hex`、`hex2bin`、`hex2int`）以及异或操作函数（`xor`）。
- `itertools`中的`product`：用于生成 PC1 表未使用位置的所有可能组合，以穷举搜索初始密钥。
- `time`：用于记录密码分析过程的执行时间。
- `tqdm`：为密码分析过程中的循环操作提供可视化的进度条，方便用户了解分析进度。
- `datetime`：用于将分析过程所花费的时间以易读的格式进行展示。

## 使用方法

**导入模块与初始化**

```python
from des import Des, P_Table, PC2_Table, LOOP_Table, PC1_Table
from DifferentialCryptandysis import DifferentialCryptandysis
import random
import bin2hex
import time
import datetime
```

首先导入所需的模块和类，包括自定义的`Des`类和`DifferentialCryptandysis`类，以及其他必要的函数和模块。

然后创建`Des`类的实例，指定 DES 加密的轮数，并可以选择设置一个已知的密钥（用于测试恢复密钥的正确性）：

```python
round = 1
des = Des(round)
# des.set_key('f93fde5a749fe21b')  # 如果有已知密钥，可在此设置，用于后续验证恢复密钥的准确性
```

接着创建`DifferentialCryptandysis`类的实例，传入`Des`实例、差分分析的次数`M`和测试时使用的明文对数`testnum`

```python
dc = DifferentialCryptandysis(des, 5, 10)  # 这里的 5 是分析次数 M，10 是测试明文对数 testnum，可根据需求调整
```

**执行差分密码分析**
调用`analyze`方法开始进行差分密码分析：

```python
start = time.time()
key = dc.analyze()
end = time.time()
during = datetime.timedelta(seconds=end - start)
print('==> Finish analysing, it spends {}'.format(during))
```

分析过程中，会根据设定的参数生成随机明文对，进行多次差分分析，逐步计算每个 S 盒可能的密钥差分，最终尝试恢复出原始的 DES 密钥，并打印出分析所花费的时间。

**验证恢复密钥的有效性**
获取原始密钥信息（如果之前设置了已知密钥）：

```python
print('\nOriginal key informations:')
des.get_key()
```

然后使用恢复出的密钥对大量随机明文进行加密测试，验证其是否与原始 DES 加密结果一致：

```python
N = 1000
print('\nThe predicted key is {}, testing {} random plaintext...'.format(key, N))
d = Des(round)
d.set_key(key)
for i in tqdm.trange(N):
    plaintext = bin2hex([random.randint(0, 1) for _ in range(64)], 16)
    ciphertext_gt = des.encode(plaintext)  # groundtrue
    ciphertext_pre = d.encode(plaintext)  # predict
    plaintext_pre = d.decode(ciphertext_gt)
    if ciphertext_gt!= ciphertext_pre or plaintext!= plaintext_pre:
        print('\nAttack unsuccessfully!')
        exit(0)
print('\nAll test pass. Attack successfully!')
```

如果所有测试都通过，即恢复出的密钥能够正确加密和解密随机明文，与原始 DES 加密结果一致，则判定攻击成功；否则，攻击失败并打印相应信息。

## 代码结构与关键函数说明

- `DifferentialCryptandysis`类
  - `__init__`方法：初始化差分密码分析所需的各种参数和数据结构，包括`Des`实例、轮数、测试明文对数、预计算的 S 盒差分表、存储密钥差分的列表、用于密钥恢复的位置信息、测试明文对及其密文，以及进度条对象。
  - `Sxor`方法：预先计算 S 盒的差分表，通过遍历所有可能的输入和输入差分，计算输出差分，并将满足条件的输入值记录在差分表中。
  - `analyze`方法：执行`M`次`analyze_single`方法进行差分分析，然后调用`find_key`方法找到可能的 48 位密钥，接着通过`key_reverse`和`get_initial_key`方法尝试恢复 64 位初始密钥，并返回最终恢复的密钥。
  - `analyze_single`方法：生成一对随机明文，计算其经过`F`函数后的输出差分，根据差分表更新`prob_key`列表，记录每个 S 盒可能的密钥差分。
  - `get_initial_key`方法：通过穷举 PC1 表未使用位置的组合，尝试恢复初始 64 位密钥。对于每个组合，将 48 位密钥扩展到 56 位，再扩展到 64 位，然后进行位移和 S 盒替换操作，检查是否满足特定的明文密文关系，若满足则找到正确的密钥。
  - `key_reverse`方法：将 48 位密钥转换为 56 位，再调用`get_initial_key`方法尝试恢复 64 位初始密钥，返回是否成功找到密钥的结果。
  - `find_key`方法：基于`prob_key`中每个 S 盒的密钥差分统计信息，找出出现频率最高的字节组合，拼接成可能的 48 位密钥。
  - `generateP`方法：生成一对随机明文，其中一个是另一个的右半部分随机化后的结果，用于差分分析。

## 实现结果

![image-20241225202604023](C:\Users\HUAWEI\AppData\Roaming\Typora\typora-user-images\image-20241225202604023.png)

## 注意事项

- 差分密码分析是一种密码攻击技术，在实际应用中，应确保使用的加密算法和密钥管理机制足够安全，以防止此类攻击。
- 本工具中的`Des`类和相关的置换表、S 盒等实现应与标准的 DES 算法保持一致，否则可能导致分析结果不准确。
- 增加差分分析的次数`M`和测试明文对数`testnum`可以提高恢复密钥的准确性，但也会增加计算时间和资源消耗。在实际使用中，需要根据具体情况权衡分析效率和准确性。
- 本工具仅用于学习和研究目的，请勿用于非法的密码破解活动。在进行任何密码相关的测试和实验时，应遵循法律法规和道德规范，确保不侵犯他人的隐私和安全权益。