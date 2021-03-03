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


def frequency(txt) -> dict:
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


"""
Class
"""


class Scytale:

    def __init__(self, message, nb_columns, encrypted=True):
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

    def separate_message(self):
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

    def table_filling(self):
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

    def table_reading(self):
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

    def decrypt(self):
        """
        Decrypt the message
        :return unecrypted message:
        """
        return self.table_reading()

    def get_clear(self):
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

    def __init__(self, message, nb_shift=0, nb_m_shift=1, auto_shift=True, multiple_shift=False, encrypted=True):
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

    def decrypt(self, message, shift):
        """
        Decrypt a shift encrypted message
        :param message:
        :param shift:
        :return unencrypted message:
        """
        unencrypted_message = ''.join([chr(ord(letter) + shift) for letter in message])
        return unencrypted_message

    def get_shift(self, message):
        """
        Get the shift of a message
        :param message:
        :return shift:
        """
        freqs = frequency(message)
        letter = max(freqs.keys(), key=lambda x: freqs[x])
        shift = ord(" ") - ord(letter)
        return shift

    def auto_decrypt(self, message):
        """
        Auto decrypt a shift encoded message
        :param message:
        :return auto unencrypted message:
        """
        unencrypted_message = self.decrypt(message, self.get_shift(message))
        return unencrypted_message

    def m_shift(self):
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

    def get_clear(self):
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

    def __init__(self, message, encrypted=True):
        self.message = message
        self.encrypted = encrypted
        self.size_repetition = 5
        self.key = self.get_key()
        self.clear_message = self.get_clear()

    def get_repetition(self, indice=0):
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
        return False

    def get_key(self):
        message_size = len(self.message)
        repetition_distance, required_distance = message_size, message_size // 400
        indice = 0

        while repetition_distance > required_distance:
            repetition = self.get_repetition(indice)
            print(repetition)
            repetition_distance = pgcd(repetition['distance'], repetition_distance)
            indice = repetition['indice_i'] + 1

        vi_key = repetition_distance

        return vi_key

    def decrypt(self):
        return Shift(self.message, nb_m_shift=self.key, multiple_shift=True).clear_message

    def get_clear(self):
        if self.encrypted:
            message = self.decrypt()
        else:
            message = self.message
        return message


"""
Main
"""
if __name__ == '__main__':
    messages = import_messages()  # get messages
    message1 = Scytale(messages["message1"], 3).clear_message
    message2 = Shift(messages['message2']).clear_message
    message3 = Shift(messages['message3']).clear_message
    message4 = Shift(messages['message4'], nb_m_shift=2, multiple_shift=True).clear_message
    message5 = Vigenere(messages['message5'])
