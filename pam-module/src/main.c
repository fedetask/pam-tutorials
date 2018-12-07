#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <stdint.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>



PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc,
				   const char **argv)
{
	int code;
	const char *username = NULL;
	const char *password = NULL;

	/* Super secure hard-coded username and password */
	const char *right_username = "user";
	const char *right_password = "password";

	/* Asking the application for an  username */
	code = pam_get_user(handle, &username, "USERNAME: ");
	if (code != PAM_SUCCESS) {
		fprintf(stderr,"Can't get username");
		return PAM_PERM_DENIED;
	}

	/* Asking the application for a password */
	code = pam_get_authtok(handle, PAM_AUTHTOK, &password, "PASSWORD: ");
	if (code != PAM_SUCCESS) {
		fprintf(stderr,"Can't get password");
		return PAM_PERM_DENIED;
	}

	/* Check that received username and password are correct. Obviously, don't do this. */
	if (strcmp(username, right_username) == 0 && strcmp(password, right_password) == 0) {
		printf("Welcome, user");
		return PAM_SUCCESS;
	} else {
		fprintf(stderr, "Wrong username or password");
		return PAM_PERM_DENIED;
	}

}
