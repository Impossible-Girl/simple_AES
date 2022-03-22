# -*- coding: utf-8 -*-
"""
Created on Tue May 11 17:12:56 2021
This is an AES cipher implementation.
@author: Katarzyna Smarz
"""
import numpy as np
def stringToBits(string):
    bin_array = []
    for i in range(len(string)):
        bin_array.append(ord(string[i]))
    for j in range(len(bin_array)):
        bin_array[j]=bin(bin_array[j])
    return bin_array

def stringToHex(string):
    hex_array = []
    for i in range(len(string)):
        hex_array.append(ord(string[i]))
    for j in range(len(hex_array)):
        hex_array[j]=hex(hex_array[j])
    return hex_array

Sbox = [
    ["0x63", "0x7c", "0x77", "0x7b", "0xf2", "0x6b", "0x6f", "0xc5", "0x30", "0x01", "0x67", "0x2b", "0xfe", "0xd7", "0xab", "0x76"],
    ["0xca", "0x82", "0xc9", "0x7d", "0xfa", "0x59", "0x47", "0xf0", "0xad", "0xd4", "0xa2", "0xaf", "0x9c", "0xa4", "0x72", "0xc0"],
    ["0xb7", "0xfd", "0x93", "0x26", "0x36", "0x3f", "0xf7", "0xcc", "0x34", "0xa5", "0xe5", "0xf1", "0x71", "0xd8", "0x31", "0x15"],
    ["0x04", "0xc7", "0x23", "0xc3", "0x18", "0x96", "0x05", "0x9a", "0x07", "0x12", "0x80", "0xe2", "0xeb", "0x27", "0xb2", "0x75"],
    ["0x09", "0x83", "0x2c", "0x1a", "0x1b", "0x6e", "0x5a", "0xa0", "0x52", "0x3b", "0xd6", "0xb3", "0x29", "0xe3", "0x2f", "0x84"],
    ["0x53", "0xd1", "0x00", "0xed", "0x20", "0xfc", "0xb1", "0x5b", "0x6a", "0xcb", "0xbe", "0x39", "0x4a", "0x4c", "0x58", "0xcf"],
    ["0xd0", "0xef", "0xaa", "0xfb", "0x43", "0x4d", "0x33", "0x85", "0x45", "0xf9", "0x02", "0x7f", "0x50", "0x3c", "0x9f", "0xa8"],
    ["0x51", "0xa3", "0x40", "0x8f", "0x92", "0x9d", "0x38", "0xf5", "0xbc", "0xb6", "0xda", "0x21", "0x10", "0xff", "0xf3", "0xd2"],
    ["0xcd", "0x0c", "0x13", "0xec", "0x5f", "0x97", "0x44", "0x17", "0xc4", "0xa7", "0x7e", "0x3d", "0x64", "0x5d", "0x19", "0x73"],
    ["0x60", "0x81", "0x4f", "0xdc", "0x22", "0x2a", "0x90", "0x88", "0x46", "0xee", "0xb8", "0x14", "0xde", "0x5e", "0x0b", "0xdb"],
    ["0xe0", "0x32", "0x3a", "0x0a", "0x49", "0x06", "0x24", "0x5c", "0xc2", "0xd3", "0xac", "0x62", "0x91", "0x95", "0xe4", "0x79"],
    ["0xe7", "0xc8", "0x37", "0x6d", "0x8d", "0xd5", "0x4e", "0xa9", "0x6c", "0x56", "0xf4", "0xea", "0x65", "0x7a", "0xae", "0x08"],
    ["0xba", "0x78", "0x25", "0x2e", "0x1c", "0xa6", "0xb4", "0xc6", "0xe8", "0xdd", "0x74", "0x1f", "0x4b", "0xbd", "0x8b", "0x8a"],
    ["0x70", "0x3e", "0xb5", "0x66", "0x48", "0x03", "0xf6", "0x0e", "0x61", "0x35", "0x57", "0xb9", "0x86", "0xc1", "0x1d", "0x9e"],
    ["0xe1", "0xf8", "0x98", "0x11", "0x69", "0xd9", "0x8e", "0x94", "0x9b", "0x1e", "0x87", "0xe9", "0xce", "0x55", "0x28", "0xdf"],
    ["0x8c", "0xa1", "0x89", "0x0d", "0xbf", "0xe6", "0x42", "0x68", "0x41", "0x99", "0x2d", "0x0f", "0xb0", "0x54", "0xbb", "0x16"]
    ]
invSbox = [
    ["0x52", "0x09", "0x6a", "0xd5", "0x30", "0x36", "0xa5", "0x38", "0xbf", "0x40", "0xa3", "0x9e", "0x81", "0xf3", "0xd7", "0xfb"],
    ["0x7c", "0xe3", "0x39", "0x82", "0x9b", "0x2f", "0xff", "0x87", "0x34", "0x8e", "0x43", "0x44", "0xc4", "0xde", "0xe9", "0xcb"],
    ["0x54", "0x7b", "0x94", "0x32", "0xa6", "0xc2", "0x23", "0x3d", "0xee", "0x4c", "0x95", "0x0b", "0x42", "0xfa", "0xc3", "0x4e"],
    ["0x08", "0x2e", "0xa1", "0x66", "0x28", "0xd9", "0x24", "0xb2", "0x76", "0x5b", "0xa2", "0x49", "0x6d", "0x8b", "0xd1", "0x25"],
    ["0x72", "0xf8", "0xf6", "0x64", "0x86", "0x68", "0x98", "0x16", "0xd4", "0xa4", "0x5c", "0xcc", "0x5d", "0x65", "0xb6", "0x92"],
    ["0x6c", "0x70", "0x48", "0x50", "0xfd", "0xed", "0xb9", "0xda", "0x5e", "0x15", "0x46", "0x57", "0xa7", "0x8d", "0x9d", "0x84"],
    ["0x90", "0xd8", "0xab", "0x00", "0x8c", "0xbc", "0xd3", "0x0a", "0xf7", "0xe4", "0x58", "0x05", "0xb8", "0xb3", "0x45", "0x06"],
    ["0xd0", "0x2c", "0x1e", "0x8f", "0xca", "0x3f", "0x0f", "0x02", "0xc1", "0xaf", "0xbd", "0x03", "0x01", "0x13", "0x8a", "0x6b"],
    ["0x3a", "0x91", "0x11", "0x41", "0x4f", "0x67", "0xdc", "0xea", "0x97", "0xf2", "0xcf", "0xce", "0xf0", "0xb4", "0xe6", "0x73"],
    ["0x96", "0xac", "0x74", "0x22", "0xe7", "0xad", "0x35", "0x85", "0xe2", "0xf9", "0x37", "0xe8", "0x1c", "0x75", "0xdf", "0x6e"],
    ["0x47", "0xf1", "0x1a", "0x71", "0x1d", "0x29", "0xc5", "0x89", "0x6f", "0xb7", "0x62", "0x0e", "0xaa", "0x18", "0xbe", "0x1b"],
    ["0xfc", "0x56", "0x3e", "0x4b", "0xc6", "0xd2", "0x79", "0x20", "0x9a", "0xdb", "0xc0", "0xfe", "0x78", "0xcd", "0x5a", "0xf4"],
    ["0x1f", "0xdd", "0xa8", "0x33", "0x88", "0x07", "0xc7", "0x31", "0xb1", "0x12", "0x10", "0x59", "0x27", "0x80", "0xec", "0x5f"],
    ["0x60", "0x51", "0x7f", "0xa9", "0x19", "0xb5", "0x4a", "0x0d", "0x2d", "0xe5", "0x7a", "0x9f", "0x93", "0xc9", "0x9c", "0xef"],
    ["0xa0", "0xe0", "0x3b", "0x4d", "0xae", "0x2a", "0xf5", "0xb0", "0xc8", "0xeb", "0xbb", "0x3c", "0x83", "0x53", "0x99", "0x61"],
    ["0x17", "0x2b", "0x04", "0x7e", "0xba", "0x77", "0xd6", "0x26", "0xe1", "0x69", "0x14", "0x63", "0x55", "0x21", "0x0c", "0x7d"]
    ]
def createStateMatrix(input):
      state=[]
      state.append([input[0]])
      state.append([input[1]])
      state.append([input[2]])
      state.append([input[3]])
      index = 4
      for i in range (3):
          for j in range(4):
              state[j].append(input[index])
              index = index + 1
      return state
  
def polyMul(poly1, poly2):
    poly1= str(bin(poly1))
    poly2 = str(bin(poly2))
    poly1 = poly1[2:]
    poly2 = poly2[2:]
    poly1 = list(poly1)
    poly2 = list(poly2)
    for i in range(len(poly1)):
        poly1[i] = int(poly1[i])
    for i in range(len(poly2)):
        poly2[i] = int(poly2[i])
    aes_poly = [1, 0, 0, 0, 1, 1, 0, 1, 1]
    mul = np.polymul(poly1, poly2)
    for i in range(len(mul)):
        mul[i] = mul[i]%2
    while len(mul) > 8:
        quotient, remainder = np.polydiv(mul, aes_poly)
        mul = remainder
        for i in range(len(mul)):
            mul[i] = mul[i]%2
    mul = mul.astype(int)
    mul = mul.astype(str)
    mul = mul.tolist()
    mul = ''.join(mul)
    mul = int(mul, 2)
    return mul

#please note that the two functions below are purely for AES polynomials with coefficients - columns from the state matrix,
#which are always 3rd grade
def polyAdd(poly1, poly2):
    result = []
    for i in range(4):
        to_insert = poly1[3 - i] ^ poly2[3 - i]
        result.insert(0, to_insert)
    return result

def polyMulWord(poly):
    result = []
    result.append((polyMul(0x02, poly[0]))^(polyMul(0x03, poly[1]))^poly[2]^poly[3])
    result.append(poly[0]^(polyMul(0x02, poly[1]))^(polyMul(0x03, poly[2]))^poly[3])
    result.append(poly[0]^poly[1]^(polyMul(0x02, poly[2]))^(polyMul(0x03, poly[3])))
    result.append((polyMul(0x03, poly[0]))^poly[1]^poly[2]^(polyMul(0x02, poly[3])))
    return result

def subBytes(state):
    for i in range(4):
        for j in range(4):
            byte = state[i][j]
            if (len(byte) < 4):
                byte = byte[2:]
                byte = byte.zfill(2)
                byte = "0x" + byte
            row = int(byte[2], 16)
            column = int(byte[3], 16)
            byte = Sbox[row][column]
            state[i][j] = byte
    return state

def shiftRows(state):
    for i in range(1, 4):
        for j in range(i):
            to_move = state[i].pop(0)
            state[i].append(to_move)
    return state

def mixColumns(state):
    for i in range(4):
        column = []
        for j in range(4):
            column.append(int(state[j][i], 16))
        column = polyMulWord(column)
        for k in range (4):
            to_append = hex(column[k])
            if (len(to_append) < 4):
                to_append = to_append[2:]
                to_append = to_append.zfill(2)
                to_append = "0x" + to_append
            state[k][i] = to_append
    return state

def addRoundKey(state, round_key):
    key = []
    for i in range(4):
        key.append(round_key[i][0:4])
        key.append("0x" + round_key[i][4:6])
        key.append("0x" + round_key[i][6:8])
        key.append("0x" + round_key[i][8:10])
    for i in range (4):
        for j in range(4):
            state[j][i] = hex(int(state[j][i], 16) ^ int(key[0], 16))
            if len(state[j][i]) < 4:
                state[j][i] = state[j][i][2:]
                state[j][i] = state[j][i].zfill(2)
                state[j][i] = "0x" + state[j][i]
            key.pop(0)
    return state

def subWord(key):
    key = key[2:]
    key_array = []
    for i in range(4):
        key_array.append(key[0+i*2:2+i*2])
    for i in range(4):
        byte = key_array[i]
        row = int(byte[0], 16)
        column = int(byte[1], 16)
        byte = Sbox[row][column]
        key_array[i] = byte
    key = "0x"
    for part in key_array:
        part = part[2:]
        key = key + part
    return key

def rotWord(key):
    key = key[2:]
    key_array = []
    for i in range(4):
        key_array.append(key[0+i*2:2+i*2])
    to_move = key_array.pop(0)
    key_array.append(to_move)
    key = "0x"
    for part in key_array:
        key = key + part
    return key

def keyExpansion(key):
    key_schedule = []
    key_schedule.append(key[0:10])
    for i in range(7):
        key_part = "0x" + key[10 + (i*8) : 18 + (i*8)]
        key_schedule.append(key_part)
    rcon = 0x01000000
    for i in range(8, 60):
        prev_word = key_schedule[len(key_schedule) - 1]
        nk_prev_word = key_schedule[len(key_schedule) - 8]
        if (i%8 == 0):
            prev_word = rotWord(prev_word)
            prev_word = subWord(prev_word)
            prev_word = int(prev_word, 16) ^ rcon*int(pow(2, i/8 - 1))
            prev_word = hex(prev_word)
        elif ((i-4)%8 == 0):
            prev_word = subWord(prev_word)
        to_append = int(prev_word, 16) ^ int(nk_prev_word, 16)
        to_append = hex(to_append)
        if (len(to_append) < 10):
            to_append = to_append[2:]
            to_append = to_append.zfill(8)
            to_append = "0x" + to_append
        key_schedule.append(to_append)
    return key_schedule

def encrypt(input, key):
    state = createStateMatrix(input)
    keys = keyExpansion(key)
    state = addRoundKey(state, keys[0:4])
    for i in range(13):
        state = subBytes(state)
        state = shiftRows(state)
        state = mixColumns(state)
        state = addRoundKey(state, keys[(4 + 4*i) : (8 + 4*i)])
    state = subBytes(state)
    state = shiftRows(state)
    state = addRoundKey(state, keys[56:60])
    output = "0x"
    for k in range(4):
        for j in range(4):
            output = output + state[j][k][2:]
    print(output)
    return output

def invShiftRows(state):
    for i in range(1, 4):
        for j in range(i):
            to_move = state[i].pop(3)
            state[i].insert(0, to_move)
    return state

def invSubBytes(state):
    for i in range(4):
        for j in range(4):
            byte = state[i][j]
            if (len(byte) < 4):
                byte = byte[2:]
                byte = byte.zfill(2)
                byte = "0x" + byte
            row = int(byte[2], 16)
            column = int(byte[3], 16)
            byte = invSbox[row][column]
            state[i][j] = byte
    return state

def invPolyMulWord(poly):
    result = []
    result.append((polyMul(0x0e, poly[0]))^(polyMul(0x0b, poly[1]))^(polyMul(0x0d, poly[2]))^(polyMul(0x09, poly[3])))
    result.append((polyMul(0x09, poly[0]))^(polyMul(0x0e, poly[1]))^(polyMul(0x0b, poly[2]))^(polyMul(0x0d, poly[3])))
    result.append((polyMul(0x0d, poly[0]))^(polyMul(0x09, poly[1]))^(polyMul(0x0e, poly[2]))^(polyMul(0x0b, poly[3])))
    result.append((polyMul(0x0b, poly[0]))^(polyMul(0x0d, poly[1]))^(polyMul(0x09, poly[2]))^(polyMul(0x0e, poly[3])))
    return result

def invMixColumns(state):
    for i in range(4):
        column = []
        for j in range(4):
            column.append(int(state[j][i], 16))
        column = invPolyMulWord(column)
        for k in range (4):
            to_append = hex(column[k])
            if (len(to_append) < 4):
                to_append = to_append[2:]
                to_append = to_append.zfill(2)
                to_append = "0x" + to_append
            state[k][i] = to_append
    return state
def decrypt(input, key):
    state = createStateMatrix(input)
    keys = keyExpansion(key)
    state = addRoundKey(state, keys[56:60])
    for i in range(13):
        state = invShiftRows(state)
        state = invSubBytes(state)
        state = addRoundKey(state, keys[(52 - 4*i) : (56 - 4*i)])
        state = invMixColumns(state)
    state = invShiftRows(state)
    state = invSubBytes(state)
    state = addRoundKey(state, keys[0:4])
    output = "0x"
    for k in range(4):
        for j in range(4):
            output = output + state[j][k][2:]
    print(output)
    return output

def hexToList(input):
    output = []
    output.append(input[:4])
    for i in range(int((len(input)-4)/2)):
        output.append("0x" + input[(4+i*2):(6+i*2)])
    return output


def hello():
    print("Hello! It's really simple AES implementation. What do you want to do today?")
    print("0: Encrypt a message")
    print("1: Decrypt a message")
    choice = int(input("Please choose one option: "))
    if (choice == 0):
        message = input("Please enter a hex message 32-character in length with 0x included:\n")
        key = input("Please enter a hex key 66-character in length with 0x included:\n")
        message = hexToList(message)
        encrypt(message, key)
    elif (choice == 1):
        message = input("Please enter a hex message 32-character in length with 0x included:\n")
        key = input("Please enter a hex key 66-character in length with 0x included:\n")
        message = hexToList(message)
        decrypt(message, key)
hello()