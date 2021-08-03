"""
Algorithms from Introduction of Modern Cryptography: Second Edition
"""

from typing import List

from colorama import Fore, Style

# the distributions of letters in the english alphabet (a-z)
plain_dist = [
    0.082,
    0.015,
    0.028,
    0.043,
    0.127,
    0.022,
    0.02,
    0.061,
    0.07,
    0.002,
    0.008,
    0.04,
    0.024,
    0.067,
    0.015,
    0.019,
    0.001,
    0.06,
    0.063,
    0.091,
    0.028,
    0.01,
    0.024,
    0.002,
    0.02,
    0.001,
]

ALPHABET_LENGTH = 26
START_OF_ALPHABET = ord("a")


def frequency_distribution(cipher_text: str) -> List[float]:
    """
    Calculate the frequency distribution of each letter in the ciphertext
    Input:
        ciphertext: the ciphertext we are calculating the distribution for
    """
    cipher_text = cipher_text.lower()
    letter_frequency = [0] * ALPHABET_LENGTH

    for i in range(0, len(cipher_text)):
        letter_frequency[ord(cipher_text[i]) - START_OF_ALPHABET] += 1 / len(
            cipher_text
        )
    return letter_frequency


def summation_i(p: List[float], q: List[float], j: int) -> float:
    """
    Calculate the summation for the improved letter frequency attack
    Input:
        p: the frequency of the ith letter in normal english text
        q: the frequency of the ith letter of the alphabet in the ciphertext
        j: the shift value we are calculating for
    """
    I = 0
    for i in range(0, ALPHABET_LENGTH):
        I += p[i] * q[(i + j) % ALPHABET_LENGTH]
    return I


def summation_s(q: List[float]) -> float:
    """
    Calculate the summation for the improved letter frequency attack
    Input:
        q: the frequency of the ith letter of the alphabet in the ciphertext
    """
    S = 0
    for i in range(0, len(q)):
        S += pow(q[i], 2)
    return S


def shift_decrypt(key: int, cipher_text: str) -> str:
    """
    Decrypt and print ciphertext encrypted using a shift cipher using key
    Input:
        key: the value the message m is shifted by
        cipher_text: the ciphertext we are decrypting
    """
    decrypted_text = ""
    for letter in cipher_text:
        decrypted_text += chr(
            (ord(letter) - START_OF_ALPHABET - key) % ALPHABET_LENGTH
            + START_OF_ALPHABET
        )
    return decrypted_text


def vegenere_decrypt(key: int, cipher_text: str) -> str:
    """
    Decrypt and print ciphertext encrypted using a shift cipher using key
    Input:
        key: the word the message m is encrypted with
        cipher_text: the ciphertext we are decrypting
    """
    decrypted_text = ""
    index = 0

    for letter in cipher_text.lower():
        cipher_letter = ord(letter) - START_OF_ALPHABET
        key_letter = ord(key[index]) - START_OF_ALPHABET
        decrypted_text += chr(
            (cipher_letter - key_letter) % ALPHABET_LENGTH + START_OF_ALPHABET
        )
        index = (index + 1) % len(key)
    return decrypted_text


def get_shift_key(cipher_text: str) -> int:
    """
    Determine the key used to encrypt given ciphertext using a shift
    Input:
        cipher_text: the ciphertext we are attempting to decrypt
    """
    cipher_dist = frequency_distribution(cipher_text)
    summations = [0] * ALPHABET_LENGTH
    for k in range(0, ALPHABET_LENGTH):
        summations[k] = abs(summation_i(plain_dist, cipher_dist, k) - 0.065)
    return summations.index(min(summations))


def get_vigenere_key_word(cipher_text: str, key_length: int) -> str:
    """
    Determine the key_word used to encrypt given ciphertext using a vigenere cipher
    Input:
        cipher_text: the ciphertext we are attempting to decrypt
        key_length: the length of our key word
    """
    key_word = ""
    for i in range(0, key_length):
        stream = ""
        for j in range(i, len(cipher_text), key_length):
            stream += cipher_text[j]

        key = get_shift_key(stream)
        key_word += chr(ord("a") + key)
    return key_word


def get_stream(cipher_text: str, j: int, start: int) -> str:
    """
    Get the stream
    Input:
        cipher_text: the ciphertext we are attempting to decrypt
        j: getting the stream which is every jth letter
        start: letter to start at
    """
    message = ""
    for i in range(start, len(cipher_text), j):
        message += cipher_text[i]
    return message


def shift_encrypt(plain_text: str, shift: int) -> str:
    """
    Encrypt using a shift cipher
    Input:
        plain_text: the plaintext we are encrypting
        shift: the shift we want to use to encrypt
    """
    cipher_text = ""
    for letter in plain_text:
        new_index = (ord(letter) - START_OF_ALPHABET + shift) % ALPHABET_LENGTH
        cipher_text += chr(new_index + START_OF_ALPHABET)
    return cipher_text


def vigenere_encrypt(plain_text: str, key: str) -> str:
    """
    Encrypt using a vigenere cipher
    Input:
        plain_text: the plaintext we are encrypting
        key: the key we want to use to encrypt
    """
    cipher_text = ""
    for i in range(len(plain_text)):
        value = (ord(plain_text[i]) + ord(key[i % len(key)])) % ALPHABET_LENGTH
        cipher_text += chr(value + START_OF_ALPHABET)
    return cipher_text


def index_of_coincidence_attack(cipher_text: str):
    """
    Determine the key used to encrypt given ciphertext using a vigenere cipher
    Input:
        cipher_text: the ciphertext we are attempting to decrypt
    """
    MAX_WORD_LENGTH = 1000
    key_length = 0

    for j in range(1, MAX_WORD_LENGTH + 1):
        for k in range(0, j):
            text = get_stream(cipher_text, j, k)
            cipher_dist = frequency_distribution(text)
            value = abs(summation_s(cipher_dist) - 0.065)
            if value < 0.01:
                key_length = j
                break

        if key_length:
            break

    key_word = get_vigenere_key_word(cipher_text, key_length)
    print("{}Vigenere Key: {}{}".format(Fore.GREEN, Style.RESET_ALL, str(key_word)))
    decrypted_text = vegenere_decrypt(key_word, cipher_text)
    print(
        "{}Cipher Text: {}{}".format(Fore.MAGENTA, Style.RESET_ALL, cipher_text.lower())
    )
    print("{}Decrypted Text: {}{}\n".format(Fore.CYAN, Style.RESET_ALL, decrypted_text))


def improved_letter_frequency_attack(cipher_text: str):
    """
    Determine the key used to encrypt given ciphertext using a shift cipher
    Input:
        cipher_text: the ciphertext we are attempting to decrypt
    """
    key = get_shift_key(cipher_text)
    shift_decrypt(key, cipher_text)
    print("{}Shift Key: {}{}".format(Fore.GREEN, Style.RESET_ALL, str(key)))
    decrypted_text = shift_decrypt(key, cipher_text)
    print("{}Cipher Text: {}{}".format(Fore.MAGENTA, Style.RESET_ALL, cipher_text))
    print("{}Decrypted Text: {}{}\n".format(Fore.CYAN, Style.RESET_ALL, decrypted_text))
