#include <stdio.h>
#include <stdlib.h>
#include <cstring> 
int main(int argc, char * argv[]) {
	//read the master password
	FILE * masterfile = fopen("master.txt", "r");
	char mastername[100];
	char masterpwd[100];
	fgets(mastername, 100, masterfile);
	fgets(masterpwd, 100, masterfile);
	fclose(masterfile);
	
	//read the user password
	if(argc < 2) {		
		printf("Please provide an input filename containing the username/pwd\n");
		return 1;
	}
	FILE * userfile = fopen(argv[1], "r");
	char username[100];
	char userpwd[100];
	fgets(username, 100, userfile);
	fgets(userpwd, 100, userfile);
	fclose(userfile);
	
	
	//is user authorized?
	int authorized = 0;
	
	printf("Welcome, ");
	printf(username);
	
	if (strcmp(username, mastername) == 0 && strcmp(userpwd, masterpwd) == 0) {
		authorized = 1;
	}
	if (authorized != 0) {
		printf("Nuclear controls ready.\nShall we play a game?\n");
	}
	else {
		printf("User not authorized.\n");
	}
	return 0;
}
