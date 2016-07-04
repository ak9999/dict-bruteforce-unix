#!/usr/bin/env python3
import sys
import crypt
import spwd

'''
Author: Abdullah Khan
Program: cracker.py
Description: Dictionary-based /etc/shadow file cracker.
Usage: cracker.py <path/to/dictionary/file>
'''

def crack(username, enc_password, dictionary):
    if not dictionary:
        exit(1)

    salt = enc_password[0:20]
    for word in dictionary:
        potential = crypt.crypt(word, salt)
        if potential == enc_password:
            print('Username: {0}\tPassword: {1}'.format(username, word))
            break



def main():
    if len(sys.argv) != 2 or len(sys.argv) > 2:
        print('Usage: {0} <path/to/dictionary/file>'.format(sys.argv[0]))
        exit(1)
    else:
        words = []
        with open(sys.argv[1], 'r') as f:
            for line in f.readlines():
                words.append(line.strip())
        shadow = spwd.getspall()
        for entry in shadow:
            if entry[1] != '!!' and entry[1] != '*':
                crack(entry[0], entry[1], words)

if __name__ == '__main__':
    main()