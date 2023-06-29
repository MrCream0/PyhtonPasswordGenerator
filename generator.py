"""Module for generating a random password"""


import random as r
import string as s


class PasswordGenerator:
    def generate_password(length=8):
        """Generate a random password of a given length"""
        password = ''
        for _ in range(length):
            password += r.choice(s.ascii_letters)
        return password

    def generate_password_with_symbols(length=8):
        """Generate a random password of a given length with symbols"""
        password = ''
        for _ in range(length):
            password += r.choice(s.ascii_letters + s.digits + s.punctuation)
        return password


    def generate_password_with_symbols_and_spaces(length=8):
        """Generate a random password of a given length with symbols and spaces"""
        password = ''
        for _ in range(length):
            password += r.choice(s.ascii_letters + s.digits + s.punctuation + ' ')
        return password


    if __name__ == '__main__':
        print(generate_password())
        print(generate_password_with_symbols())
        print(generate_password_with_symbols_and_spaces())