#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_USERFILE_SIZE 1024
#define USERSFILE "users"

bool auth_user(const char *, const char *);
void change_pass(const char *, const char *);
/**
 * @brief R
 *
 * @param user
 * @param password
 */
bool auth_user(const char *user, const char *password)
{
	FILE *f = fopen(USERSFILE, "r");
	char content[MAX_USERFILE_SIZE];
	int pos = 0;
	bool authenticated = false;

	int c;
	/* Reading the file until EOF and filling content */
	while ((c = fgetc(f)) != EOF) {
		content[pos++] = c;
	}

	char *userfield = strtok(content, ":");
	char *passfield = strtok(NULL, "\n");

	while (1) {
		if (strcmp(user, userfield) == 0 &&
		    strcmp(password, passfield) == 0) {
			authenticated = true;
			break;
		}
		userfield = strtok(NULL, ":");
		if (userfield == NULL)
			break;
		passfield = strtok(NULL, "\n");
		if (passfield == NULL)
			break;
	}
	return authenticated;
}

void change_pass(const char *username, const char *password)
{
	FILE *f = fopen(USERSFILE, "wr");
	char content[MAX_USERFILE_SIZE];
	int pos = 0;
	bool authenticated = false;

	int filepos = 0;

	int c;
	/* Reading the file until EOF and filling content */
	while ((c = fgetc(f)) != EOF) {
		content[pos++] = c;
	}

	char *userfield = strtok(content, ":");
	char *passfield = strtok(NULL, "\n");
	filepos += strlen(userfield) + strlen(passfield) + 2;
	while (1) {
		if (strcmp(username, userfield) == 0 &&
		    strcmp(password, passfield) == 0) {
			authenticated = true;
			break;
		}
		userfield = strtok(NULL, ":");
		if (userfield == NULL)
			break;
		passfield = strtok(NULL, "\n");
		if (passfield == NULL)
			break;
	}
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc,
				   const char **argv)
{
	int pam_code;

	const char *username = NULL;
	const char *password = NULL;

	/* Asking the application for an  username */
	pam_code = pam_get_user(handle, &username, "USERNAME: ");
	if (pam_code != PAM_SUCCESS) {
		fprintf(stderr, "Can't get username");
		return PAM_PERM_DENIED;
	}

	/* Asking the application for a password */
	pam_code =
		pam_get_authtok(handle, PAM_AUTHTOK, &password, "PASSWORD: ");
	if (pam_code != PAM_SUCCESS) {
		fprintf(stderr, "Can't get password");
		return PAM_PERM_DENIED;
	}

	/* Checking the PAM_DISALLOW_NULL_AUTHTOK flag: if on, we can't accept empty passwords */
	if (flags & PAM_DISALLOW_NULL_AUTHTOK) {
		if (password == NULL || strcmp(password, "") == 0) {
			fprintf(stderr,
				"Null authentication token is not allowed!.");
			return PAM_PERM_DENIED;
		}
	}

	/*Auth user reads a file with usernames and passwords and returns true if username
	 * and password are correct. Obviously, you must not save clear text passwords */
	if (auth_user(username, password)) {
		printf("Welcome, user");
		return PAM_SUCCESS;
	} else {
		fprintf(stderr, "Wrong username or password");
		return PAM_PERM_DENIED;
	}
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
				const char **argv)
{
	/* This struct contains the expiry date of the account */
	struct tm expiry_date;
	expiry_date.tm_mday = 31;
	expiry_date.tm_mon = 12;
	expiry_date.tm_year = 2020;
	expiry_date.tm_sec = 0;
	expiry_date.tm_min = 0;
	expiry_date.tm_hour = 0;

	time_t expiry_time;
	time_t current_time;

	/* Getting time_t value for expiry_date and current date */
	expiry_time = mktime(&expiry_date);
	current_time = time(NULL);

	/* Checking the account is not expired */
	if (current_time > expiry_time) {
		return PAM_PERM_DENIED;
	} else {
		return PAM_SUCCESS;
	}
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
			      const char **argv)
{
	/* Environment variable name */
	const char *env_var_name = "USER_FULL_NAME";

	/* User full name */
	const char *name = "John Smith";

	/* String in which we write the assignment expression */
	char env_assignment[100];

	/* If application asks for establishing credentials */
	if (flags & PAM_ESTABLISH_CRED)
		/* We create the assignment USER_FULL_NAME=John Smith */
		sprintf(env_assignment, "%s=%s", env_var_name, name);
	/* If application asks to delete credentials */
	else if (flags & PAM_DELETE_CRED)
		/* We create the assignment USER_FULL_NAME, withouth equal,
		 * which deletes the environment variable */
		sprintf(env_assignment, "%s", env_var_name);

	/* In this case credentials do not have an expiry date,
	 * so we won't handle PAM_REINITIALIZE_CRED */

	pam_putenv(pamh, env_assignment);
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
				   const char **argv)
{
	const char *username;
	char dir_path[512];

	/* Get the username from PAM */
	pam_get_item(pamh, PAM_USER, (const void **)&username);

	/* Creating directory path string */
	sprintf(dir_path, "/home/%s", username);

	mkdir(dir_path, 0770);

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
				    const char **argv)
{
	const char *username;
	char dir_path[512];

	/* Get the username from PAM */
	pam_get_item(pamh, PAM_USER, (const void **)&username);

	/* Creating directory path string */
	sprintf(dir_path, "/home/%s", username);

	rmdir(dir_path);

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
				const char **argv)
{
	const char *username;
	const char *cur_password;
	const char *new_password;
	/* We always return PAM_SUCCESS for the preliminary check */
	if (flags & PAM_PRELIM_CHECK) {
		return PAM_SUCCESS;
	}

	/* Get the username */
	pam_get_item(pamh, PAM_USER, (const void **)&username);

	/* We're not handling the PAM_CHANGE_EXPIRED_AUTHTOK specifically
	 * since we do not have expiry dates for our passwords. */
	if ((flags & PAM_UPDATE_AUTHTOK) ||
	    (flags & PAM_CHANGE_EXPIRED_AUTHTOK)) {
		/* Ask the application for the password. From this module function, pam_get_authtok()
		 * with item type PAM_AUTHTOK asks for the new password with the retype. Therefore,
		 * to ask for the current password we must use PAM_OLDAUTHTOK. */
		pam_get_authtok(pamh, PAM_OLDAUTHTOK, &cur_password,
				"Insert current password: ");

		if (auth_user(username, cur_password)) {
			pam_get_authtok(pamh, PAM_AUTHTOK, &new_password,
					"New password: ");
			change_pass(username, new_password);
		} else {
			return PAM_PERM_DENIED;
		}
	}
	return PAM_SUCCESS;
}

