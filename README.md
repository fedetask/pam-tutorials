# Linux PAM tutorials
This repo contains the code from my [Linux PAM tutorials](https://fedetask.com/category/linux-pam/).

## pam-application
Contains a simple C program that does authentication against a PAM configuration file.
#### Contents:
- main.c is the program
- pam_example is the PAM configuration file that must be put in /etc/pam.d/
#### Dependencies
Requires to have the `libpam-dev` package installed. Check the correct name for your distribution
#### Building
Run `gcc -o run_pam.o main.c -lpam -lpam_misc`
