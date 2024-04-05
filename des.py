#FUNCTION DECLARATIONS
def permutate(data, p_matrix):
    result = 0
    
    for i in range(len(p_matrix)):
        #get bit
        bit = (((0x1 << p_matrix[i]) & data) >> p_matrix[i]) << i
        #put bit into result
        result = result + bit
    
    return result

def s_box(data):
    pass

def feistel_function(data, key):
    pass
    
def feistel_round(data, key):
    pass
    

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
                         56, 48, 40, 31, 23, 16, 8, 0,
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

s_box_table = [14, 0, 4, 15, 13, 7, 1, 4,
               3, 14, 15, 2, 11, 13, 8, 1,
               3, 10, 10, 6, 6, 12, 12, 11, 
               5, 9, 9, 5, 0, 3, 7, 8,
               4, 15, 1, 12, 14, 8, 8, 2,
               13, 4, 6, 9, 2, 1, 11, 7,
               15, 5, 12, 11, 9, 3, 7, 14,
               3, 10, 10, 0, 5, 6, 0, 13]

#PROGRAM START
user_input = input("Enter plaintext: ")

print(user_input)

plaintext = bytes(user_input, 'utf-8')
plaintext_length = len(plaintext)

block_num = (plaintext_length // 8) + 1
padding_size = 8 - (plaintext_length % 8)

#print debugging info
print(plaintext_length)
print("% s % s" % (block_num, padding_size))

ciphertext = bytearray(block_num * 8)

for i in range(block_num):
    block = 0
    for j in range(8):
        if not (j >= (8 - padding_size) and i == (block_num - 1)):
            temp = plaintext[(i * 8) + j] & 0xff
            block = block + (temp << (j * 8))
            
    for j in range(8):
        temp = (block & (0xff << (j * 8))) >> (j * 8)
        ciphertext[(i * 8) + j] = temp
        
    print(block)

print(ciphertext)
