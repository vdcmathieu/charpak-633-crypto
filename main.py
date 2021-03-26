# -*- coding: utf-8 -*-

"""
This entire document is meant to be the solution for the Institut Villebon Georges Charpak's crypto courses.
"""
__author__ = "Mathieu VAN DE CATSIJE"
__email__ = "mathieu.van-de-catsije@universite-paris-saclay.fr"
__status__ = "development"

"""
Library import
"""

import rotors as rt

"""
Basic functions
"""


def import_messages() -> dict:
    """
    Import all messages from message directory
    :return dictionary of message:
    """
    msg = {}
    for i in range(1, 9):
        with open('messages/message{0}.txt'.format(i), 'r', encoding="utf8") as file:
            msg["message{0}".format(i)] = file.read()
    return msg


def frequency(txt: str) -> dict:
    """
    Get the frequency of each char in a text
    :param txt:
    :return dictionary of the freq:
    """
    return {c: txt.count(c) for c in set(txt)}


def pgcd(a: int, b: int) -> int:
    """
    Get the PGCD between two number
    :param a:
    :param b:
    :return pgdc(a,b):
    """
    if b == 0:
        return a
    else:
        r = a % b
        return pgcd(b, r)


def rotate(array: list, n: int = 1) -> list:
    """
    Rotate a list n times
    :param array:
    :param n:
    :return rotated list:
    """
    return array[-n:] + array[:-n]


"""
Class
"""


class Scytale:

    def __init__(self, message: str, nb_columns: int, encrypted: bool = True):
        """
        Init
        :param message:
        :param nb_columns:
        :param encrypted:
        """
        self.encrypted = encrypted
        self.nbColumns = nb_columns
        self.message = message
        self.table = self.table_filling()
        self.clear_message = self.get_clear()

    def separate_message(self) -> list:
        """
        Serapate the original message into chunck to complete column
        :return array with message's chunks:
        """
        chunks, chunk_size = len(self.message), len(self.message) / self.nbColumns
        chunk_size_mem = chunk_size
        chunk_size = int(chunk_size)
        if chunk_size_mem > chunk_size:
            chunk_size += 1
        msgs = [self.message[i:i + chunk_size] for i in range(0, chunks, chunk_size)]
        return msgs

    def table_filling(self) -> list:
        """
        Fill the table with message's chunks
        :return table fields according to the number of column provided:
        """
        messages = self.separate_message()
        table = [[] for i in range(self.nbColumns)]
        for column in range(self.nbColumns):
            for letter in messages[column]:
                table[column].append(letter)
        return table

    def table_reading(self) -> str:
        """
        Read table to decrypt message
        :return unecrypted message:
        """
        unencrypted_message_table = []
        table_length, column_length = len(self.table), len(self.table[0])
        for i in range(column_length):
            for j in range(table_length):
                try:
                    unencrypted_message_table.append(self.table[j][i])
                except IndexError:
                    nothing_happen = "well that's true"
        unencrypted_message = ''.join(unencrypted_message_table)
        return unencrypted_message

    def decrypt(self) -> str:
        """
        Decrypt the message
        :return unecrypted message:
        """
        return self.table_reading()

    def get_clear(self) -> str:
        """
        Check if message is encrypted if so get the clear message
        :return clear message:
        """
        if self.encrypted:
            message = self.decrypt()
        else:
            message = self.message
        return message


class Shift:

    def __init__(self, message: str, nb_shift: int = 0, nb_m_shift: int = 1, auto_shift: bool = True,
                 multiple_shift: bool = False, encrypted: bool = True):
        """
        Init
        :param message:
        :param nb_shift:
        :param nb_m_shift:
        :param auto_shift:
        :param multiple_shift:
        :param encrypted:
        """
        self.encrypted = encrypted
        self.message = message
        self.auto_shift = auto_shift
        self.nb_shift = nb_shift
        self.multiple_shift = multiple_shift
        self.nb_m_shift = nb_m_shift
        self.clear_message = self.get_clear()

    def decrypt(self, message: str, shift: int) -> str:
        """
        Decrypt a shift encrypted message
        :param message:
        :param shift:
        :return unencrypted message:
        """
        unencrypted_message = ''.join([chr(ord(letter) + shift) for letter in message])
        return unencrypted_message

    def get_shift(self, message: str) -> int:
        """
        Get the shift of a message
        :param message:
        :return shift:
        """
        freqs = frequency(message)
        letter = max(freqs.keys(), key=lambda x: freqs[x])
        shift = ord(" ") - ord(letter)
        return shift

    def auto_decrypt(self, message: str) -> str:
        """
        Auto decrypt a shift encoded message
        :param message:
        :return auto unencrypted message:
        """
        unencrypted_message = self.decrypt(message, self.get_shift(message))
        return unencrypted_message

    def m_shift(self) -> str:
        """
        Decrypt a message with multiple shift
        :return unencrypted message:
        """
        part_table = [[] for i in range(self.nb_m_shift)]
        trans_message, unecrypted_message = [], []
        for index, letter in enumerate(self.message):
            part_table[index % self.nb_m_shift].append(letter)
        for part in part_table:
            trans_message.append(self.auto_decrypt(''.join(part)))
        for i in range(len(max(trans_message, key=len))):
            for j in range(len(trans_message)):
                try:
                    unecrypted_message.append(trans_message[j][i])
                except IndexError:
                    nothing_happen = "well that's true"
        return ''.join(unecrypted_message)

    def get_clear(self) -> str:
        """
        Check the message condition and give the correct protocol to obtain clear message
        :return clear message:
        """
        if self.encrypted and self.auto_shift and not self.multiple_shift:
            message = self.auto_decrypt(self.message)
        elif self.encrypted and not self.auto_shift and not self.multiple_shift:
            message = self.decrypt(self.message, self.nb_shift)
        elif self.encrypted and self.multiple_shift:
            message = self.m_shift()
        else:
            message = self.message
        return message


class Vigenere:

    def __init__(self, message: str, encrypted: bool = True):
        """
        Init
        :param message:
        :param encrypted:
        """
        self.message = message
        self.encrypted = encrypted
        self.size_repetition = 4
        self.key = self.get_key()
        self.clear_message = self.get_clear()

    def get_repetition(self, indice: int = 0) -> dict:
        """
        Get repetition of size x in a text
        :param indice:
        :return first repetition found based on given indice:
        """
        for i in range(indice, len(self.message) - self.size_repetition):
            for j in range(i + self.size_repetition, len(self.message) - self.size_repetition):
                if self.message[i:i + self.size_repetition] == self.message[j:j + self.size_repetition]:
                    return {
                        "txt": [self.message[i:i + self.size_repetition],
                                self.message[j:j + self.size_repetition]],
                        "indice_i": i,
                        "indice_j": j,
                        "distance": j - i
                    }

    def get_key(self) -> int:
        """
        Get vigenere key by getting the smallest distance between two chars repetition
        :return Vigenere key:
        """
        message_size = len(self.message)
        repetition_distance, required_distance = message_size, message_size // 200
        indice = 0

        while repetition_distance > required_distance:
            repetition = self.get_repetition(indice)
            if indice == 0:
                repetition_distance = repetition['distance']
            else:
                repetition_distance = pgcd(repetition['distance'], repetition_distance)
            indice = repetition['indice_i'] + 1
            if indice > len(self.message):
                return False

        vi_key = repetition_distance

        return vi_key

    def decrypt(self) -> str:
        """
        Decrypt Vigenere by using the multiple shift and the key given by get_key
        :return unencrypted message:
        """
        return Shift(self.message, nb_m_shift=self.key, multiple_shift=True).clear_message

    def get_clear(self) -> str:
        """
        Check the message condition and give the correct protocol to obtain clear message
        :return clear message:
        """
        if self.encrypted:
            message = self.decrypt()
        else:
            message = self.message
        return message


class Enigma:

    def __init__(self, txt: str, ch_rotors: list = None, init_config: list = None, encrypted: bool = True):
        """
        Init
        :param txt:
        :param ch_rotors:
        :param init_config:
        :param encrypted:
        """
        if ch_rotors is None:
            ch_rotors = [0, 1, 2]
        if init_config is None:
            init_config = [0, 0, 0]
        self.message = txt
        self.encrypted = encrypted
        self.rotation, self.inverse_rotation = [0, 0, 0], [0, 0, 0]
        self.rotors = self.set_rotors(ch_rotors, init_config)
        self.initial_rotors = self.rotors
        self.clear_message = self.get_clear()

    def get_rotors(self):
        return self.rotors

    def get_inverse(self) -> list:
        """
        Get rotors inverse to decrypt
        :return rotors inverse to decrypt:
        """
        return [rotor[::-1] for rotor in self.rotors]

    def rotate_rotors(self, inverse: bool = False):
        """
        Rotate rotors
        :param inverse:
        :return rotate rotors or inverse rotors:
        """
        if not inverse:
            self.rotors[0] = rotate(self.rotors[0])
            self.rotation[0] += 1
            if self.rotation[0] % 256 == 0:
                self.rotors[1] = rotate(self.rotors[1])
                self.rotation[1] += 1
                if self.rotation[1] % 256 == 0:
                    self.rotors[2] = rotate(self.rotors[2])
                    self.rotation[2] += 1
        else:
            self.rotors[0] = rotate(self.rotors[0], -1)
            self.inverse_rotation[0] += 1
            if self.inverse_rotation[0] % 256 == 0:
                self.rotors[1] = rotate(self.rotors[1], -1)
                self.inverse_rotation[1] += 1
                if self.inverse_rotation[1] % 256 == 0:
                    self.rotors[2] = rotate(self.rotors[2], -1)
                    self.inverse_rotation[2] += 1

    @staticmethod
    def set_rotors(choosen_rotors, init_config) -> list:
        """
        Set rotors based on provided initial config
        :return set rotors:
        """
        return [rotate(li, init_config[index]) for index, li in enumerate(rt.get_rotors(choosen_rotors))]

    def decrypt(self) -> str:
        unencrypted_message = ""
        for letter in self.message:
            unencrypted_message += chr(self.rotors[0].index(self.rotors[1].index(self.rotors[2].index(ord(letter)))))
            self.rotate_rotors()
        return unencrypted_message

    def oldCrypt(self) -> list:
        encrypted_message = []
        print(f'Rotors\n{self.rotors[0]}\n{self.rotors[1]}\n{self.rotors[2]}\n')
        for letter in self.message:
            encrypted_letter = chr(self.get_rotors()[2][self.get_rotors()[1][self.get_rotors()[0][ord(letter)]]])
            encrypted_message += encrypted_letter
            self.rotate_rotors()
            print(f'{[letter]} -> {[encrypted_letter]} ({ord(letter)}>{self.rotors[0][ord(letter)]}>{self.rotors[1][self.rotors[0][ord(letter)]]}>{self.rotors[2][self.rotors[1][self.rotors[0][ord(letter)]]]}) \n')
            print(f'Rotors\n{self.rotors[0]}\n{self.rotors[1]}\n{self.rotors[2]}\n')
        return encrypted_message

    def crypt(self) -> list:
        encrypted_message = []
        for index, letter in enumerate(self.message):
            rotors = self.get_rotors()
            r0, r1, r2 = index, index // 256, (index // 256) // 256
            rotor0, rotor1, rotor2 = rotate(rotors[0], r0), rotate(rotors[1], r1), rotate(rotors[2], r2)
            encrypted_letter = chr(rotor2[rotor1[rotor0[ord(letter)]]])
            encrypted_message.append(encrypted_letter)
            # Log
            print(f'Rotors positions:\n0:{rotor0}\n1:{rotor1}\n2:{rotor2}\n')
            print(f'Translation:\n{[letter]} -> {[encrypted_letter]} ({ord(letter)}>{rotor0[ord(letter)]}>{rotor1[rotor0[ord(letter)]]}>{rotor2[rotor1[rotor0[ord(letter)]]]})')
            print(f'\n-----\n')
        return encrypted_message

    def get_clear(self) -> str:
        """
        Check the message condition and give the correct protocol to obtain clear message
        :return clear message:
        """
        if self.encrypted:
            return self.decrypt()
        else:
            initial_message = self.message
            self.message = self.crypt()
            return initial_message


"""
Main
"""
if __name__ == '__main__':
    messages = import_messages()  # get messages
    # message1 = Scytale(messages["message1"], 3)
    # message2 = Shift(messages['message2'])
    # message3 = Shift(messages['message3'])
    # message4 = Shift(messages['message4'], nb_m_shift=2, multiple_shift=True)
    # message5 = Vigenere(messages['message5'])
    # message6 = Vigenere(messages["message6"])
    # message7 = Vigenere(messages['message7'])
    # print(message7.clear_message)
    with open('test.txt', 'r', encoding="utf8") as file:
        message = file.read()
    enigma = Enigma(message[:10], ch_rotors=[0, 1, 2], init_config=[0, 0, 0], encrypted=False)
    print(f'\n{enigma.message}')

    with open("test2.txt", 'r', encoding='utf8') as file:
        messageToDecrypt = file.read()
    enigma2 = Enigma(messageToDecrypt, ch_rotors=[0, 1, 2], init_config=[0, 0, 0], encrypted=True)
    print(f'\n----\n\n{[(letter,ord(letter)) for letter in enigma2.message]}')
