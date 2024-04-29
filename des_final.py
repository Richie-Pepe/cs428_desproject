# DES Algorithm Project CS 428 April 2024
# Members: Owen Lawrence, Richard Pepe, Peter Nguyen, Raymond Soto
# Programming Language: Python

# sbox and other matrix constants came from 
# https://en.m.wikipedia.org/wiki/DES_supplementary_material

# test cases assisted from this online DES calculator

# History:
# 1 Richard - initial code
# 2 Peter - changed a few bytes in sbox 7 & 8. Added header description comments
#           added a comments about sbox and user input
# 3 Peter and Richard - Got Encryption working
# 4 Raymond and Owen - Got Decryption working

import array as arr

#FUNCTION DECLARATIONS
def permutate(data, p_matrix, data_length):
    result = 0
    for i in range(len(p_matrix)):
    
        #get bit
        bit = (((0x1 << (data_length - (p_matrix[i] + 1))) & data) >> (data_length - (p_matrix[i] + 1))) << (len(p_matrix) - (i + 1))
        
        #put bit into result
        result += bit
    return result

def s_box(data):
    result = 0
    # For each group of 6 bits, the sbox_in gets each of those 6 bits
    #  which is used as row & col input into the the s_box_table variable
    #  since the s_box_table is formatted differently, there's no
    #  need to extract the row and col from a group of 6 bits.
    for i in range(8):
        sbox_in = ((0x3f << (48 - (6 * (i + 1)))) & data) >> (48 - (6 * (i + 1)))
        sbox_out = s_box_table[i][sbox_in]
        temp = sbox_out << (32 - (4 * (i + 1)))
        result += temp
    return result

def subkey_shift(subkey):
    bit = (subkey & 0x8000000) >> 27
    subkey = ((subkey << 1) | bit) & 0xFFFFFFF
    return subkey

def key_gen(master_key):
    bitmask_28 = 0xFFFFFFF
    key_list = []
    
    key = permutate(master_key, pc_1, 64)
    
    subkey_left = ((bitmask_28 << 28) & key) >> 28
    subkey_right = bitmask_28 & key

    for i in range(16):
        for j in range(key_schedule[i]):
            subkey_left = subkey_shift(subkey_left)
            subkey_right = subkey_shift(subkey_right)
            
        final_subkey = ((subkey_left << 28) + subkey_right)
        final_subkey = permutate(final_subkey, pc_2, 56)
        
        key_list.append(final_subkey)
        
    return key_list

def feistel_function(data, key):
    data = permutate(data, p_box_expansion, 32)  # Expand
    data = data ^ key                            # XOR with key
    data = s_box(data)                           # Apply s-box
    data = permutate(data, p_box_straight, 32)   # Straight permutation
    return data

def feistel_encryption_rounds(data, key_arr):
    bitmask_32 = 0xFFFFFFFF
    
    #split data
    data_left = ((bitmask_32 << 32) & data) >> 32
    data_right = bitmask_32 & data
    
    for x in range(16):
        #run feistel function
        result_right = data_left ^ feistel_function(data_right, key_arr[x])
        result_left = data_right
        data_right = result_right
        data_left = result_left
        
    #combine results
    result = (result_right << 32) + result_left

    return result

def feistel_decryption_rounds(data, key_arr):
    bitmask_32 = 0xFFFFFFFF
    
    data_left = ((bitmask_32 << 32) & data) >> 32
    data_right = bitmask_32 & data
    
    for x in range(15, -1, -1):  # Reverse the key order for decryption
        result_right = data_left ^ feistel_function(data_right, key_arr[x])
        result_left = data_right
        data_right = result_right
        data_left = result_left
        
    result = (result_right << 32) + result_left
    
    return result

def convert_hex_to_text(hex_data, padding_size):
    # Convert hexadecimal data to bytes
    bytes_data = hex_data.to_bytes(8, byteorder='big')
    # Strip any null bytes and padding
    string_data = bytes_data.decode('utf-8', errors='ignore').rstrip(chr(padding_size))
    return string_data

# CONSTANTS
sample_master_key = 0x0000000000
key_schedule = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

#PERMUTATION DEFINITIONS
#note - numbers in matrices will always be 1 less than in module
#       module presentation (i.e. 01 will be 00, 15 will be 14, etc.)
#       this makes bitwise operations easier to work with
p_box_expansion =   [31, 0, 1, 2, 3, 4,
                      3, 4, 5, 6, 7, 8,
                      7, 8, 9, 10, 11, 12,
                      11, 12, 13, 14, 15, 16,
                      15, 16, 17, 18, 19, 20,
                      19, 20, 21, 22, 23, 24,
                      23, 24, 25, 26, 27, 28,
                      27, 28, 29, 30, 31, 0]
                      
p_box_straight =    [15, 6, 19, 20, 28, 11, 27, 16, 
                     0, 14, 22, 25, 4, 17, 30, 9,
                     1, 7, 23, 13, 31, 26, 2, 8,
                     18, 12, 29, 5, 21, 10, 3, 24]
                      
initial_permutation =   [57, 49, 41, 33, 25, 17, 9, 1,
                         59, 51, 43, 35, 27, 19, 11, 3,
                         61, 53, 45, 37, 29, 21, 13, 5,
                         63, 55, 47, 39, 31, 23, 15, 7,
                         56, 48, 40, 32, 24, 16, 8, 0,
                         58, 50, 42, 34, 26, 18, 10, 2,
                         60, 52, 44, 36, 28, 20, 12, 4,
                         62, 54, 46, 38, 30, 22, 14, 6]
                         
final_permutation =     [39, 7, 47, 15, 55, 23, 63, 31,
                         38, 6, 46, 14, 54, 22, 62, 30,
                         37, 5, 45, 13, 53, 21, 61, 29,
                         36, 4, 44, 12, 52, 20, 60, 28,
                         35, 3, 43, 11, 51, 19, 59, 27,
                         34, 2, 42, 10, 50, 18, 58, 26, 
                         33, 1, 41, 9, 49, 17, 57, 25,
                         32, 0, 40, 8, 48, 16, 56, 24]
                         
pc_1 =  [56, 48, 40, 32, 24, 16, 8, 0,
         57, 49, 41, 33, 25, 17, 9, 1,
         58, 50, 42, 34, 26, 18, 10, 2, 
         59, 51, 43, 35, 62, 54, 46, 38,
         30, 22, 14, 6, 61, 53, 45, 37,
         29, 21, 13, 5, 60, 52, 44, 36,
         28, 20, 12, 4, 27, 19, 11, 3]

pc_2 =  [13, 16, 10, 23, 0, 4, 2, 27,
         14, 5, 20, 9, 22, 18, 11, 3,
         25, 7, 15, 6, 26, 19, 12, 1,
         40, 51, 30, 36, 46, 54, 29, 39, 
         50, 44, 32, 47, 43, 48, 38, 55,
         33, 52, 45, 41, 49, 35, 28, 31]

s_box_table = [[14, 0, 4, 15, 13, 7, 1, 4,
                2, 14, 15, 2, 11, 13, 8, 1,
                3, 10, 10, 6, 6, 12, 12, 11, 
                5, 9, 9, 5, 0, 3, 7, 8,
                4, 15, 1, 12, 14, 8, 8, 2,
                13, 4, 6, 9, 2, 1, 11, 7,
                15, 5, 12, 11, 9, 3, 7, 14,
                3, 10, 10, 0, 5, 6, 0, 13],

                [15, 3, 1, 13, 8, 4, 14, 7,
                6, 15, 11, 2, 3, 8, 4, 14,
                9, 12, 7, 0, 2, 1, 13, 10,
                12, 6, 0, 9, 5, 11, 10, 5,
                0, 13, 14, 8, 7, 10, 11, 1,
                10, 3, 4, 15, 13, 4, 1, 2,
                5, 11, 8, 6, 12, 7, 6, 12,
                9, 0, 3, 5, 2, 14, 15, 9],

                [10, 13, 0, 7, 9, 0, 14, 9, 
                6, 3, 3, 4, 15, 6, 5, 10,
                1, 2, 13, 8, 12, 5, 7, 14,
                11, 12, 4, 11, 2, 15, 8, 1,
                13, 1, 6, 10, 4, 13, 9, 0,
                8, 6, 15, 9, 3, 8, 0, 7,
                11, 4, 1, 15, 2, 14, 12, 3,
                5, 11, 10, 5, 14, 2, 7, 12],

                [7, 13, 13, 8, 14, 11, 3, 5,
                0, 6, 6, 15, 9, 0, 10, 3,
                1, 4, 2, 7, 8, 2, 5, 12,
                11, 1, 12, 10, 4, 14, 15, 9,
                10, 3, 6, 15, 9, 0, 0, 6, 
                12, 10, 11, 1, 7, 13, 13, 8,
                15, 9, 1, 4, 3, 5, 14, 11,
                5, 12, 2, 7, 8, 2, 4, 14],

                [2, 14, 12, 11, 4, 2, 1, 12,
                7, 4, 10, 7, 11, 13, 6, 1,
                8, 5, 5, 0, 3, 15, 15, 10,
                13, 3, 0, 9, 14, 8, 9, 6,
                4, 11, 2, 8, 1, 12, 11, 7,
                10, 1, 13, 14, 7, 2, 8, 13,
                15, 6, 9, 15, 12, 0, 5, 9,
                6, 10, 3, 4, 0, 5, 14, 3],

                [12, 10, 1, 15, 10, 4, 15, 2,
                9, 7, 2, 12, 6, 9, 8, 5,
                0, 6, 13, 1, 3, 13, 4, 14,
                14, 0, 7, 11, 5, 3, 11, 8,
                9, 4, 14, 3, 15, 2, 5, 12,
                2, 9, 8, 5, 12, 15, 3, 10,
                7, 11, 0, 14, 4, 1, 10, 7,
                1, 6, 13, 0, 11, 8, 6, 13],

                [4, 13, 11, 0, 2, 11, 14, 7,
                15, 4, 0, 9, 8, 1, 13, 10,
                3, 14, 12, 3, 9, 5, 7, 12, 
                5, 2, 10, 15, 6, 8, 1, 6,
                1, 6, 4, 11, 11, 13, 13, 8,
                12, 1, 3, 4, 7, 10, 14, 7, 
                10, 9, 15, 5, 6, 0, 8, 15,
                0, 14, 5, 2, 9, 3, 2, 12],

                [13, 1, 2, 15, 8, 13, 4, 8, 
                6, 10, 15, 3, 11, 7, 1, 4,
                10, 12, 9, 5, 3, 6, 14, 11,
                5, 0, 0, 14, 12, 9, 7, 2,
                7, 2, 11, 1, 4, 14, 1, 7, 
                9, 4, 12, 10, 14, 8, 2, 13, 
                0, 15, 6, 12, 10, 9, 13, 0,
                15, 3, 3, 5, 5, 6, 8, 11]]

# MAIN PROGRAM
user_input = input("Enter plaintext: ") # in ascii not hex

#get padding and length info
plaintext = bytes(user_input, 'utf-8')
plaintext_length = len(plaintext)
block_num = (plaintext_length // 8) + 1
padding_size = 8 - (plaintext_length % 8)

#print debugging info
print("Plaintext Length: % s bytes" % (plaintext_length))
print("% s Blocks\n% s Padded bytes\n" % (block_num, padding_size))

#ciphertext = bytearray(block_num * 8)
ciphertext = arr.array('Q', [0 for i in range(block_num)])
keys = key_gen(sample_master_key)

for i in range(block_num):
    block = 0
    
    # split data into blocks
    for j in range(8):
        if not (j >= (8 - padding_size) and i == (block_num - 1)):
            temp = plaintext[(i * 8) + j] & 0xff
            block += (temp << ((8 - (j + 1)) * 8))
            
    # add padding
    if i == (block_num - 1):
        for j in range(padding_size):
            block += (padding_size << (j * 8))
    print("Plaintext block % s: % s" % (i, hex(block)))
    
    block = permutate(block, initial_permutation, 64)
    block = feistel_encryption_rounds(block, keys)
    block = permutate(block, final_permutation, 64)
    
    ciphertext[i] = block

# Display encryption results
print("\nEncryption Results:")
print("Master Key: % s" % (hex(sample_master_key)))

for i in range(block_num):
    print("Ciphertext block %s: %s" % (i, hex(ciphertext[i])))

# Decryption and conversion to text
decrypted_text = ""
for i in range(block_num):
    block = ciphertext[i]
    
    block = permutate(block, initial_permutation, 64)
    block = feistel_decryption_rounds(block, keys)
    block = permutate(block, final_permutation, 64)
    
    decrypted_text += convert_hex_to_text(block, padding_size if i == block_num - 1 else 0)

# Display decryption results
print("\nDecryption Results:\n")
print("Decrypted plaintext: '%s'" % decrypted_text)

