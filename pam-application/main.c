#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdlib.h>
#include <termios.h> /* Necessary for reading secret password from console */

#define PASS_MAX_LEN 100

/**
 * @brief Reads a secret password from command line
 *
 * @param password[] String to be filled with the password
 *
 * @return Number of char read
 */
int readPass(char password[])
{
	static struct termios oldt, newt;
	int i = 0;
	int c;

	/*saving the old settings of STDIN_FILENO and copy settings for resetting*/
	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;

	/*setting the approriate bit in the termios struct*/
	newt.c_lflag &= ~(ECHO);

	/*setting the new bits*/
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);

	/*reading the password from the console*/
	while ((c = getchar()) != '\n' && c != EOF && i < 100) {
		password[i++] = c;
	}
	password[i] = '\0';

	/*resetting our old STDIN_FILENO*/
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	return strlen(password);
}

/**
 * @brief This function performs a conversation between our application and the module.
 * It receives an array of messages in the parameters (set by the module) and sets
 * the array of responses in the parameters with the appropriate content.
 * For example, if the module calls this function with a message "login:" we are expected
 * to set the firs response with the username
 *
 * @param num_msg Number of messages from the module
 * @param msg Array of messages (set by the module, should not be modified)
 * @param resp Array of responses this function must set
 * @param appdata_ptr Pointer to additional data. The pointer received is that specified
 * in the pam_conv structure below.
 *
 * @return PAM return code
 */
int conversation(int num_msg, const struct pam_message **msg,
		 struct pam_response **resp, void *appdata_ptr)
{ /* We malloc an array of num_msg responses */
	struct pam_response *array_resp = (struct pam_response *)malloc(
		num_msg * sizeof(struct pam_response));
	for (int i = 0; i < num_msg; i++) {
		/* resp_retcode should be set to zero */
		array_resp[i].resp_retcode = 0;

		/* The message received from the module */
		const char *msg_content = msg[i]->msg;

		/* Printing the message (e.g. "login:", "Password:") */
		printf("%s", msg_content);

		char pass[PASS_MAX_LEN];

		/* This is a function that reads a line from console without printing it
		 * just like when you digit your password on sudo. I'll publish this soon */
		readPass(pass);

		/* Malloc-ing the resp string of the i-th response */
		array_resp[i].resp = (char *)malloc(strlen(pass) + 1);

		/* Writing password in the allocated string */
		strcpy(array_resp[i].resp, pass);
	}

	/* setting the param resp with our array of responses */
	*resp = array_resp;

	/* Here we return PAM_SUCCESS, which means that the conversation happened correctly.
	 * You should always check that, for example, the user didn't insert a NULL password etc */
	return PAM_SUCCESS;
}

/**
 * @brief Specifies the conversation function to use and the pointer to additional data
 */
static struct pam_conv conv = {
	conversation, /* Our conversation function */
	NULL /* We don't need additional data now*/
};

/**
 * @brief Performs a PAM authentication against out custom pam_example module.
 * Initiates pam and triggers auth, account and password rules.
 */
int main()
{
	pam_handle_t *handle = NULL;
	const char *service_name = "pam_example";
	int retval;
	char *username; /* This will be set by PAM with pam_get_item (see below) */

	retval = pam_start(service_name, NULL, &conv,
			   &handle); /* Initializing PAM */
	if (retval != PAM_SUCCESS) {
		fprintf(stderr, "Failure in pam initialization: %s",
			pam_strerror(handle, retval));
		return 1;
	}

	retval = pam_authenticate(
		handle,
		0); /* Do authentication (user will be asked for username and password)*/
	if (retval != PAM_SUCCESS) {
		fprintf(stderr, "Failure in pam authentication: %s",
			pam_strerror(handle, retval));
		return 1;
	}

	retval = pam_acct_mgmt(
		handle,
		0); /* Do account management (check the account can access the system) */
	if (retval != PAM_SUCCESS) {
		fprintf(stderr, "Failure in pam account management: %s",
			pam_strerror(handle, retval));
		return 1;
	}

	/* We now get the username given by the user */
	pam_get_item(handle, PAM_USER, (const void **)&username);
	printf("WELCOME, %s\n", username);

	printf("Do you want to change your password? (answer y/n): ");
	char answer = getc(stdin); /* Taking user answer */
	if (answer == 'y') {
		retval = pam_chauthtok(
			handle,
			0); /* Do update (user will be asked for current and new password) */
		if (retval != PAM_SUCCESS) {
			fprintf(stderr, "Failure in pam password: %s",
				pam_strerror(handle, retval));
			return 1;
		}
	}

	pam_end(handle, retval); /* ALWAYS terminate the pam transaction!! */
}
