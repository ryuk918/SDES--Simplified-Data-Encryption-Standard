

"""
Authors: ryuk918
Created date: 2020.2.15
this module encrypts/decrypts string with SDES algorithm
it enc/dec one string into another rather than binary digits
since it is simpler to store characters than binary digits
u can modify the encryption/decryption by reading from below - _translate_block_bin function
however then you may need to write the code that translates those binaries
"""

# S boxes
__S0 = [
    ['01', '00', '11', '10'],
    ['11', '10', '01', '00'],
    ['00', '10', '01', '11'],
    ['11', '01', '11', '10']
]

__S1 = [
    ['00', '01', '10', '11'],
    ['10', '00', '01', '11'],
    ['11', '00', '01', '00'],
    ['10', '01', '00', '11']
]

# permutation tables
__P4 = [1, 3, 2, 0]

__EP = [3, 0, 1, 2, 1, 2, 3, 0]

__P8 = [5, 2, 6, 3, 7, 4, 9, 8]

__IP = [1, 5, 2, 0, 3, 7, 4, 6]

__IP_INVERSE = [3, 0, 2, 4, 6, 1, 7, 5]

__P10 = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5]

# python's bult in bin() has a prefix 0b
# if x's base2 's length is lower than size
# it appends 0s to the left to match the size
# 4, size=8 -> 100 -> 00000100
def _bin(x, size=8, remove_prefix=True):

    x = bin(x)
    if remove_prefix and 'b' in x:
        x = x[2:]
    
    left = size - len(x)
    return '0'*left+x

# performs xor on 2 binary strings
# and returns that with desired size as _bin
# size was needed
# because we will use this with the key and
# query from S box from it's answer with bit size 8
def _xor(bin1, bin2, size=8):

    return _bin( int(bin1, 2) ^ int(bin2, 2), size)

# permutates x iterable's items according to path
# it is used to perform that P10, P8 e.t.c tables
# on binary string
def _permutate(x, path):

    perm = ''
    for i in path:
        perm += x[i]
    return perm

# chops binary string on half
# returns 2 dimensional list that
# 8bit -> 4bit, 4bit 2 dimensional
def _halves(itr):

    return itr[:len(itr)//2], itr[len(itr)//2: ]

# swaps halves
def _swap(block):

    halves = _halves(block)
    return halves[1] + halves[0]

# round shift to left
def _round_shift(x, shift):

    size = len(x)
    rounded = ''

    for i in range(size):
        rounded += x[(i+shift)%size]

    return rounded

# performs round shift on halves
def _round_halves(x, shift):

    halves = _halves(x)
    left = _round_shift(halves[0], shift)
    right = _round_shift(halves[1], shift)
    return left + right

# queries binary string from S box with 4bits
# this is not that useful alone
# only helper for __from_SBox(bit8)
def __from_Sbox(bit4, S):

    row_bin = bit4[0] + bit4[3]
    col_bin = bit4[1] + bit4[2]
    
    row, col = int(row_bin, 2), int(col_bin, 2)
    return S[row][col]

# returns full binary string from S boxes
def __from_SBox(bit8):

    left, right = _halves(bit8)
    return __from_Sbox(left, __S0) + __from_Sbox(right, __S1)

# now we have methods that does the basic tasks

########## KEY GENERATION ##################
# keys[0]=key1, keys[1]=key2
def get_keys(decimal):

    bin = _bin(decimal, 10)
    p10 = _permutate(bin, __P10)

    # key 1
    round1 = _round_halves(p10, 1)
    key1 = _permutate(round1, __P8)

    # key 2
    round2 = _round_halves(round1, 2)
    key2 = _permutate(round2, __P8)
    return key1, key2

# f function does the most job
# https://www.researchgate.net/figure/Simplified-DES-Algorithm_fig1_282667751
# in a nutshell
# arg ip is binary string with size 8 that was performed Initial Permutation
# and we will only modify ip's left side in the end
def _f(ip, key):

    left, right = _halves(ip)

    ep_right = _permutate(right, __EP)
    xor_with_key = _xor(ep_right, key)

    # S hairtsagnaas garah etssiin utga
    assembled = __from_SBox(xor_with_key)

    p4 = _permutate(assembled, __P4)
    xor_with_left = _xor(p4, left, 4)

    return xor_with_left + right

# bin8 - input 8bit block that have to be encryped/decrypted
# returns enc/dec 8bit block - binary
def _translate_block_bin(bin8, key1, key2):

    ip = _permutate(bin8, __IP)

    # ip -n zvvn taliig ni
    with_key1 = _f(ip, key1)
    
    swapped = _swap(with_key1)

    # ip -n baruun taliig ni
    with_key2 = _f(swapped, key2)

    return _permutate(with_key2, __IP_INVERSE)

# from the _translate_block_bin we have the encrypted/decryted block - 8bit binary
# we should convert it into the corresponding character
# so that we would store only characters instead long binary digits
def _translate_block(bin8, key1, key2):

    bin = _translate_block_bin(bin8, key1, key2)
    ascii = int(bin, 2)
    return chr(ascii)

# we can convert one character into another with _translate_block
# now we can convert string
def _translate(msg, key1, key2):

    translated = ''
    for symbol in msg:

        block = _bin(ord(symbol), 8)
        translated += _translate_block( block, key1, key2)
    
    return translated

# encryption and decryption only differs in key order

def encrypted(msg, key):

    key1, key2 = get_keys(key)
    return _translate(msg, key1, key2)

def decrypted(msg, key):
    
    key1, key2 = get_keys(key)
    return _translate(msg, key2, key1)

