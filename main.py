from colorama import Fore, Style

from encryption_breaker import (improved_letter_frequency_attack,
                                index_of_coincidence_attack)

SHIFT_CIPHERTEXT = "files/shift_ciphertext.txt"
SHIFT_PLAINTEXT = "files/shift_plaintext.txt"
VIGENERE_CIPHERTEXT = "files/vigenere_ciphertext.txt"
VIGENERE_PLAINTEXT = "files/vigenere_plaintext.txt"


def retriever_text(filename):
    with open(filename, "r") as file:
        return file.read().splitlines()


def shift_cipher():
    """
    Shift Cipher Example
    """
    shift_ciper_text = retriever_text(SHIFT_CIPHERTEXT)
    shift_plain_text = retriever_text(SHIFT_PLAINTEXT)
    expected = [8, 3]

    print(
        "{}--------------------------------------------------------------------------------------------------------------------".format(
            Fore.CYAN,
        )
    )
    print("Shift Cipher")
    print(
        "--------------------------------------------------------------------------------------------------------------------".format(
            Style.RESET_ALL
        )
    )

    for i in range(0, len(shift_ciper_text)):
        print("{}Test Case #{}:".format(Fore.BLUE, str(i + 1)))
        print(
            "{}Expected Plain Text: {}{}".format(
                Fore.RED, Style.RESET_ALL, shift_plain_text[i]
            )
        )
        print(
            "{}Expected Shift Key: {}{}".format(
                Fore.YELLOW, Style.RESET_ALL, str(expected[i])
            )
        )
        improved_letter_frequency_attack(shift_ciper_text[i])
    print(
        "{}--------------------------------------------------------------------------------------------------------------------{}".format(
            Fore.CYAN, Style.RESET_ALL
        )
    )


def vigenere_cipher():
    """
    Vigenere Cipher Example
    """
    vigenere_ciper_text = retriever_text(VIGENERE_CIPHERTEXT)
    vigenere_plain_text = retriever_text(VIGENERE_PLAINTEXT)
    expected_key = ["apple", "raquel"]

    print("{}Vigenere Cipher".format(Fore.CYAN))
    print(
        "--------------------------------------------------------------------------------------------------------------------{}".format(
            Style.RESET_ALL
        )
    )
    for i in range(0, len(vigenere_ciper_text)):
        print("{}Test Case #{}:".format(Fore.BLUE, str(i + 1)))
        print(
            "{}Expected Plain Text: {}{}".format(
                Fore.RED, Style.RESET_ALL, vigenere_plain_text[i]
            )
        )
        print(
            "{}Expected Key: {}{}".format(
                Fore.YELLOW, Style.RESET_ALL, str(expected_key[i])
            )
        )
        index_of_coincidence_attack(vigenere_ciper_text[i])
    print(
        "{}--------------------------------------------------------------------------------------------------------------------{}".format(
            Fore.CYAN, Style.RESET_ALL
        )
    )


if __name__ == "__main__":
    shift_cipher()
    vigenere_cipher()
