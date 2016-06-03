# Dictionary-based brute-forcer for UNIX

# Building
`cc shadow_cracker.c -lcrypt -o bruteforce -Wall -std=c11 -pedantic`

## Usage
`bruteforce <dictionary file>`
OR
`bruteforce <path/to/etc/shadow> <dictionary file>`

This will take a long time especially if you use a large dictionary file.

# Information:

[Wikipedia page on /etc/passwd and /etc/shadow](https://en.wikipedia.org/wiki/Passwd)

[man page for crypt](http://man7.org/linux/man-pages/man3/crypt.3.html)

