# Linux PAM tutorials
This repo contains the code from my old Linux PAM tutorials, which are not online anymore as I started working on a completely different topic and havent't ported them on a new hosting platform yet. 

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
- src/main.c is the module code
#### Dependencies
Requires `libpam-dev` package. Check the correct name for your distribution
#### Building
Run:

```bash
gcc -fPIC -fno-stack-protector -c src/main.c 
```

to compile the module and then

```bash
sudo ld -x --shared -o /lib/x86_64-linux-gnu/security/pam_example.so main.o
```

to create the shared object and install it under `/lib/x86_64-linux-gnu/security/`.

Check that this folder is the correct pam modules folder for your system.
