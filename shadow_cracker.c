/*
Author: Abdullah Khan
Program: shadow_cracker.c
Description: Dictionary-based /etc/shadow file cracker.
Build instructions: cc shadow_cracker.c -lcrypt -o bruteforce -Wall -std=c11 -pedantic
*/

/* If using a compiler that defaults to C99 or later */
#if __STDC_VERSION__ >= 199901L
#define _XOPEN_SOURCE 700
#else
#define _XOPEN_SOURCE 600
#endif /* __STDC_VERSION__ */

// STDC includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// UNIX includes
#include <unistd.h> // for crypt and access
#include <fcntl.h> // Definition of constants
#include <shadow.h> // To read /etc/shadow

void crack_passphrase(char * enc_phrase, char * username, char * dict);
void default_shadow(char * dict);
void get_shadow(FILE * pathname, char * dict);

int main(int argc, char ** argv)
{
	if(argc == 2) // Using /etc/shadow as our target.
	{
		default_shadow(argv[1]);
	}

	if(argc > 3 || argc == 1) // Tell user how to run the program.
	{
		printf("Usage: %s <dictionary file>\n", argv[0]);
		printf("Usage: %s <path/to/shadow> <dictionary file>\n", argv[0]);
		exit(EXIT_SUCCESS);
	}

	// User has supplied a shadow file and a dictionary file

	if(access(argv[1], R_OK) != 0)
	{
		// If we don't have permission to read, notify the user and quit.
		printf("Don't have permission to read %s!\n", argv[1]); exit(EXIT_SUCCESS);
	}

	FILE * passwords = fopen(argv[1], "r");
	if(passwords == NULL)
	{
		printf("Error opening %s!\n", argv[1]);
	}
	get_shadow(passwords, argv[2]);

	exit(EXIT_SUCCESS);
}

void default_shadow(char * dict)
{
	// If we don't have root permissions, notify the user and quit.
	if(geteuid() != 0) { printf("You need root privileges!\n"); exit(EXIT_SUCCESS); }

	char * dictionary = dict;

	struct spwd * shadow;
	setspent(); // Initialize position in /etc/shadow

	while((shadow = getspent()) != NULL) // Iterate through each entry
	{
		// We only want to spend time hashing against actual hashed passwords.
		if((strcmp(shadow->sp_pwdp, "!!") != 0) && (strcmp(shadow->sp_pwdp, "*") != 0))
			crack_passphrase(shadow->sp_pwdp, shadow->sp_namp, dictionary);
	}
}

void get_shadow(FILE * pathname, char * dict)
{
	struct spwd * shadow;
	fgetspent(pathname); // Initialize position in /etc/shadow

	while((shadow = fgetspent(pathname)) != NULL) // Iterate through each entry
	{
		// We only want to spend time hashing against actual hashed passwords.
		if((strcmp(shadow->sp_pwdp, "!!") != 0) && (strcmp(shadow->sp_pwdp, "*") != 0))
			crack_passphrase(shadow->sp_pwdp, shadow->sp_namp, dict);
	}
}

void crack_passphrase(char * enc_phrase, char * username, char * dict)
{
	FILE * dictionary = fopen(dict, "r");
	// Make sure we've opened it.
	if(dictionary == NULL)
	{
		printf("Problem opening file: %s\n", dict);
		exit(EXIT_FAILURE);
	}

	char buffer[256];
	while((fscanf(dictionary, "%s", buffer) != EOF))
	{
		char * salt = malloc(sizeof(char) * 20);
		strncpy(salt, enc_phrase, 20);
		char * potential_passphrase = crypt(buffer, salt);
		if(strcmp(potential_passphrase, enc_phrase) == 0)
		{
			printf("User: %s\nPassword: %s\n", username, buffer);
			break;
		}
	}
}
