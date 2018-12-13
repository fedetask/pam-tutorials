# Linux PAM tutorials
This repo contains the code from my [Linux PAM tutorials](https://github.com/fedetask/pam-tutorials/blob/master/TutorialsIndex.md). Follow my blog, [fedetask useless blog](fedetask.com) and subscribe to read my new posts!

## pam-application
Contains a simple C program that does authentication against a PAM configuration file.
#### Contents:
- main.c is the program
- pam_example is the PAM configuration file that must be put in /etc/pam.d/
#### Dependencies
Requires to have the `libpam-dev` package installed. Check the correct name for your distribution
#### Building
Run `gcc -o run_pam.o main.c -lpam -lpam_misc`

## pam-module
Contains a simple PAM module that performs authentication, account, session and password.
#### Contents:
- main.c is the module code
#### Dependencies
Requires `libpam-dev` package. Check the correct name for your distribution
#### Building
Run:
`gcc -fPIC -fno-stack-protector -c src/main.c` to compile the module
`sudo ld -x --shared -o /lib/x86_64-linux-gnu/security/pam_example.so src/main.o` to create the shared object and install it under `/lib/x86_64-linux-gnu/security/`. Check that this folder is the correct pam modules folder for your system.
