# NexHunt CTF wirte-up 要考试捏 打了一会会
## Beginner
## huntme1 记事本打开 nexus{h1dd3n_1n_7h3_f0r357_4t_n1gh7}
## huntme2 IDA反编译 根据逻辑即可 节省时间aiexp:https://chat.deepseek.com/share/oa5eb2b4n52msfkwjq
```python
byte_402060 = [
    0xF8, 0x98, 0x76, 0xFB, 0xC9, 0x0A, 0x03, 0x0D,
    0x44, 0x3D, 0x6B, 0xA6, 0xC3, 0x25, 0xA8, 0x60,
    0xFB, 0x57, 0x6C, 0xF3, 0xA1, 0xF0, 0xCF, 0x61,
    0xE6, 0xE4, 0x45, 0x16, 0x0E, 0x18, 0x3E, 0x27
]
arrays = [
    [0xA8, 0xC5, 0x83, 0xA0, 0x42, 0x2C, 0x01],
    [0xCB, 0x32, 0x20, 0xF3, 0xCF, 0x65, 0xBC],
    [0x13, 0x79, 0xB2, 0x29, 0x74, 0x61, 0xE7],
    [0xA7, 0x68, 0x76, 0x0A, 0x4E, 0x39, 0x43],
    [0xF1, 0xCD, 0x12, 0xB2, 0x7D, 0x0B, 0x2D]
]
def rol_byte(x):
    return ((x << 1) & 0xFF) | ((x >> 7) & 0xFF)
def sub_401201(a1, a2):
    tmp = ((8 * a1) ^ a1) & 0xFF
    result = ((61 * a2) ^ (tmp >> 5) ^ tmp) & 0xFF
    return result
def sub_401239(i):
    v6 = 0
    for j in range(5):
        index = (i * (j + 1) + j * j + 3) % 7
        v6 ^= arrays[j][index]
        v6 = rol_byte(v6)
    return sub_401201(v6, i)
flag = ''
for i in range(32):
    val = sub_401239(i)
    flag_char = val ^ byte_402060[i]
    flag += chr(flag_char)
print(flag)
```
## sanity check 
Discord find the rule  
base64.decode aiuok{j3pz0gw_g0_xe3_a4e3} key is nexus 维吉尼亚解密 nexus{w3lc0me_t0_th3_g4m3}
# Osint 
## special horse  
nexus{agnes_tachyon} tachyon假想的快于光速的粒子
# Blockchain
## silent flag  
the key data is 0x59524f42444c6f07656803757e68730474077306797068050705024a  
topic0 just is a signature 0x2b017342b91efedb50bcabb8f1d8e8b6e6ad1dc391c876174642e80868b896ed  
topic1 is 0x1337 
0x59524f42444c6f07656803757e68730474077306797068050705024a xor 37 
ASCII is nexus{X0R_4BI_D3C0D1NG_2025}
## chain clue
题目描述Blockchain is fully transparent  
We've made a transaction on the Sepolia testnet. Your flag is hidden somewhere in the transaction data.  
Transaction Hash: 0x1c1e14180c2e5dceefc260208199e23a8c61524dd54bd2e378cee00e14555c14   
Contract Address: 0xFb67326dAacdD9163c0eeEB9E429D7D4B6c4EBb1   
Network: Sepolia Testnet  
通过hash和address找到此合约0x60806040526040518060400160405280601c81526020017f6e65787573#7b54723463335f5468335f5472346e7334637431306e#7d
出现7b 7d ASCLL转换可得nexus{Tr4c3_Th3_Tr4ns4ct10n}


