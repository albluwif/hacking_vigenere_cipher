# -*- coding: utf-8 -*-
"""
Description: 
    This is a general hacking program to break the Vigenère cipher using 
    Kasiski examination to find the key’s length.

Author: 
    Fawzia Al-Bluwi
    CS 538 (Applied Cryptography) 
    Embry-Riddle Aeronautical University - Fall 2022
    Dec 11, 2022

"""

import re
import string
import math
import itertools
from collections import defaultdict, Counter
from operator import itemgetter

############################## Public Variables ##############################

# Get all the alphabet letters, in uppercase
ALPHABET = string.ascii_uppercase



################################## Methods ###################################

# Function: check if a given letter is in the alphabet
# Raise an error if it is not
def is_an_alphabet(text):
    assert all(c in ALPHABET for c in text)
# ----------------------------------------------------------------------------

# Function: get the difference of two alphabet indexes, limited to max length of the alphabet
def alphabet_diff(a, b):
    return ALPHABET[(ALPHABET.index(a) - ALPHABET.index(b)) % len(ALPHABET)]
# ----------------------------------------------------------------------------

# Function: get the sum of two alphabet indexes, limited to max length of the alphabet
def alphabet_sum(a, b):
    return ALPHABET[(ALPHABET.index(a) + ALPHABET.index(b)) % len(ALPHABET)]
# ----------------------------------------------------------------------------

# Function: 
# Returns a text stripped off spaces
def text2message(text):
    return "".join(c for c in text.upper() if c in ALPHABET)
# ----------------------------------------------------------------------------

# Function: 
# Takes string message (Message to encrypt), string key ( a secret key)    
# Returns a string message(encrypted message)
def vigenere_encrypt_message(message, key):
    # Check if key and message have non-alphabets
    message = text2message(message)
    key = key.upper()
    is_an_alphabet(message)
    is_an_alphabet(key)
    
    key_length = len(key)
    ciphertext = ''
    
    for i, mi in enumerate(message):
        # message Index + key Index = cipherIndex
        # key Index = Key[keyIndex mod len(Keylength)]
        ki = key[i % key_length]
        ci = alphabet_sum(mi, ki)
        ciphertext += ci
    
    return ciphertext
# ----------------------------------------------------------------------------

# Function: find the most possible key length using `Kasiski examination`_.
# Takes string ciphered text, int sequence_length (Length of analyzed substrings), int max_key_length    
# Returns an integer of the most possible key length.
def kasiski_examination(ciphertext, sequence_length, max_key_length, *, verbose=False):
    # Check if the ciphered text contains only alphabets
    is_an_alphabet(ciphertext)

    # Find positions of each substring of length `sequence_length`
    seq_positions = defaultdict(list)  # {seq: [pos]}
    for i in range(len(ciphertext) - sequence_length):
        seq_positions[ciphertext[i : i + sequence_length]].append(i)
    
    # Drop non-repeated sequences
    seq_positions = {
        seq: positions
        for seq, positions in seq_positions.items()
        if len(positions) >= 2
    }

    # If ther are no repeated segments, raise an error 
    assert len(seq_positions) > 0, f"No repeated sequences of length {sequence_length}"

    # Calculte spacings between subsequent positions for each sequence
    seq_spacings = defaultdict(list)  # {seq: [space]}
    for seq, positions in seq_positions.items():
        for a, b in zip(positions, positions[1:]):
            seq_spacings[seq].append(b - a)
    
    # Count factors (<=max_key_length) of all spacings
    factor_count = Counter()
    for spacings in seq_spacings.values():
        for space in spacings:
            for f in range(2, min(max_key_length, int(math.sqrt(space)) + 1)):
                if space % f == 0:
                    factor_count[f] += 1

    # Find the most possible key length
    key_length = factor_count.most_common()[0][0]
    
    return key_length
# ----------------------------------------------------------------------------

# Function: get the frequency of alphabets
def frequent_alphabet(text):
    return Counter(text)
# ----------------------------------------------------------------------------

# Function: create blocks of alphabets from the ciphered text, of length = key_length
def _blocks(ciphertext, key_length):
    return [''.join(ciphertext[shift + i]
                    for i in range(0, len(ciphertext) - shift, key_length))
            for shift in range(key_length)]
# ----------------------------------------------------------------------------
            
# Function: analyse the frequency of alphabet in frequent blocks
def frequency_analysis(ciphertext, key_length, text_freq):
    # Check if the ciphered text contains only alphabets
    is_an_alphabet(ciphertext)
    
    blocks = _blocks(ciphertext, key_length)
    block_freqs = [frequent_alphabet(block) for block in blocks]
    most_common_letter = text_freq.most_common()[0][0]
        
    # Find the most possible key
    key = ''
    for i, block in enumerate(blocks):
        # Note: mi + ki = ci, then ki = ci - mi
        ci = block_freqs[i].most_common()[0][0]
        ki = alphabet_diff(ci, most_common_letter)
        key += ki
    
    print(f" Most possible key:    '{key}'")
    
    return key
# ----------------------------------------------------------------------------

# Function: vigenere decrypting 
# takes a string ciphered text  and an int key
# Returns string  Decrypted message.
def vigenere_decrypt_ciphered_text(ciphertext, key):
    
    key_length = len(key)
    message = ''
    for i, ci in enumerate(ciphertext):
        # message Index + key Index = cipher Index, 
        # message Index = cipher Index - key Index
        ki = key[i % key_length]
        mi = alphabet_diff(ci, ki)
        message += mi
    
    return message
# ----------------------------------------------------------------------------




################################ Main Method #################################

# Text was generated on this site: http://metaphorpsum.com/
input_filename = "encrypted/hostiletext.txt"

# Read the file
with open(input_filename) as f:
    text = f.read()

# Identify the message (remove white spaces & make it capitals letters only)
message = text2message(text.lower())

# Identify the key
key = "MOUSE"

# Vigenere encrypt the message
ciphertext = vigenere_encrypt_message(text, key)

print(f" Text:                  {text[:50]}...")
print(f" Message:               {message[:50]}...")
print(f" Key used:              {text[:50]}...")
print(f" Ciphertext:            {ciphertext[:50]}...")

# Find the possible key length
possible_key_length = kasiski_examination(ciphertext, 5, 10)
print(f" Possible key length    {possible_key_length}")

# Get the frequency of alphabets
text_freq = frequent_alphabet(message)
text_freq.most_common(7)

# Perform frequency analysis
possible_key = frequency_analysis(ciphertext, possible_key_length, text_freq)

# Vigenere decrypt the ciphered text
decrypted_message = vigenere_decrypt_ciphered_text(ciphertext, possible_key)

print(f" Text:                  {text[:50]}...")
print(f" Message:               {message[:50]}...")
print(f" Ciphertext:            {ciphertext[:50]}...")
print(f" Decrypted:             {decrypted_message[:50]}...")

# If the decrypted message is not equal to the original message raise an error
assert decrypted_message == message, "Decryption failed"
