#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <random>
using namespace std;

void login1(char * input1, char * input2) {
	const int uname_len = 16;
	const int buffer_len = 20;
	struct {
		char code[buffer_len]; //secret code shared by all users
		char username[uname_len];
		int check_failed = 0;
		char good_code[buffer_len];
	} v;

	if(strlen(input1) > uname_len) {
		printf("Username too long, exiting.\n");
		exit(-1);
	}
	if(strlen(input2) > buffer_len) {
		printf("Input code too long, exiting.\n");
		exit(-1);
	}

	char to_drop[100];
	//read correct code from password.txt
	FILE * fp = fopen("password.txt", "r");
	fgets(to_drop, uname_len, fp);
	fgets(v.good_code, buffer_len, fp);
	fclose(fp);

	//check code is correct
	v.good_code[strlen(v.good_code)-1] = '\0';
	strcpy(v.code, input2);
	if (strcmp(v.code, v.good_code) != 0) v.check_failed = 1;

	strcpy(v.username, input1);

	if (v.check_failed == 0) printf("Login successful! Welcome %s.\n", v.username);
	else printf("Login denied.\n");

}

void login2(char * input1, char * input2) {
	struct {
		int32_t goodcanary;
		char password[25];
		int32_t canary;
		char good_username[25];
		char good_password[25];
		char username[25];
	} v;
	v.canary = 'b';
	v.goodcanary = 'b';

	//read correct username and password
	FILE * fp = fopen("password.txt", "r");
	fgets(v.good_username, 25, fp);
	fgets(v.good_password, 25, fp);
	fclose(fp);
	v.good_username[strlen(v.good_username)-1] = '\0';
	v.good_password[strlen(v.good_password)-1] = '\0';

	//load username
	strcpy(v.username, input1);

	//set up random canary
	std::mt19937 gen; //mersenne twister randomizer
	gen.seed(time(NULL) / 200000 + v.username[0] * 200 + v.username[1] * 10 + v.username[2]);
	v.goodcanary = 0;

	for (int i = 0; i < 4; i++) {
		int a = gen() % 26 + 65;
		printf("%c\n", a);
		v.goodcanary *= 256;
		v.goodcanary += a;
	}
	v.canary = v.goodcanary;

	//load password
	strcpy(v.password, input2);

	//terminate strings properly for strcmp
	v.username[24] = '\0';
	v.password[24] = '\0';
	v.good_username[24] = '\0';
	v.good_password[24] = '\0';
	
	//check canary and login success
	printf("%d %d", v.canary, v.goodcanary);
	if (v.canary != v.goodcanary) {
	/*
		printf("Stack overflow detected, exiting.\n");
		printf("ADDress of goodCanary:%p\n",&v.goodcanary);
		printf("ADDress of pass:%p\n",&v.password);
		printf("ADDress of canary:%p\n",&v.canary);
		printf("ADDress of good_username:%p\n",&v.good_username);
		printf("ADDress of good_password:%p\n",&v.good_password);
		printf("ADDress of user:%p\n",&v.username);
		for(int i=0; i<sizeof(v);i++){
		printf("Add:%p,Hex:%x,Char:%c\n",&((char*)&v)[i],((char*)&v)[i],((char*)&v)[i]);}
		*/
		exit(-1);
	}
	if (strcmp(v.username, v.good_username) == 0 && strcmp(v.password, v.good_password) == 0) printf("Login successful!\n");
	
	else printf("Login denied.\n");
	/*
		printf("ADDress of goodCanary:%p\n",&v.goodcanary);
		printf("ADDress of pass:%p\n",&v.password);
		printf("ADDress of canary:%p\n",&v.canary);
		printf("ADDress of good_username:%p\n",&v.good_username);
		printf("ADDress of good_password:%p\n",&v.good_password);
		printf("ADDress of user:%p\n",&v.username);
		for(int i=0; i<sizeof(v);i++){
		printf("Add:%p,Hex:%x,Char:%c\n",&((char*)&v)[i],((char*)&v)[i],((char*)&v)[i]);}
		*/

}

void login3(char * input1, char * input2) {
	struct {
		int32_t goodcanary;
		char username[25];
		char password[25];
		int32_t canary;
		char good_username[25];
		char good_password[25];
	} v;
	v.goodcanary = rand();
	v.canary = v.goodcanary;

	//fill out the memory
	strcpy(v.password, "abcdefghijklmnopqrstuvwx");
	strcpy(v.good_username, "abcdefghijklmnopqrstuvwx");
	strcpy(v.good_password, "abcdefghijklmnopqrstuvwx");

	//read correct username and password
	FILE * fp = fopen("password.txt", "r");
	fgets(v.good_username, 25, fp);
	fgets(v.good_password, 25, fp);
	fclose(fp);
	v.good_username[strlen(v.good_username)-1] = '\0';
	v.good_password[strlen(v.good_password)-1] = '\0';
	strcpy(v.username, input1);
	//let's load v.password carefully. we only want valid characters.
	int written_char = 0;
	int warn_user = 0;
	int ind = 0;

	while (written_char < 25) { //don't write too much
		int c = (int)input2[ind];
		if (c == 0 || (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) ) {
			//this is an okay character. load it
			v.password[ind] = (char)c;
			written_char += 1;
		}
		else if (c == 44 || c == 46) {//sometimes user types wrong characters by accident. let's remove them. 
			v.password[ind] = 0;
			written_char += 1;
		}
		else {//a strange character! let's warn the user, but don't load it
			warn_user = 1;
		}
		if (c == 0) {//reached end of string, terminate
			break;
		}
		ind += 1;
	}
	if (warn_user == 1) {
		printf("Invalid characters found and skipped. Did you type your password correctly?\n");
	}

	//terminate strings properly
	v.username[24] = '\0';
	v.password[24] = '\0';
	v.good_username[24] = '\0';
	v.good_password[24] = '\0';

	//check canary and login success
	if (v.canary != v.goodcanary) {
		printf("Stack overflow detected, exiting.\n");
		exit(-1);
	}
	
	if (strcmp(v.username, v.good_username) == 0 && strcmp(v.password, v.good_password) == 0) printf("Login successful!\n");
	else printf("Login denied.\n");
	printf("ADDress of goodCanary:%p\n",&v.goodcanary);
	printf("ADDress of user:%p\n",&v.username);
	printf("ADDress of pass:%p\n",&v.password);
	printf("ADDress of canary:%p\n",&v.canary);
	printf("ADDress of good_username:%p\n",&v.good_username);
	printf("ADDress of good_password:%p\n",&v.good_password);
	for(int i=0; i<sizeof(v);i++){
	printf("Add:%p,Hex:%x,Char:%c\n",&((char*)&v)[i],((char*)&v)[i],((char*)&v)[i]);}
}

int main(int argc, char* argv[]) {
	srand(time(NULL));
	char helpstr[] = "Use: login -? <username> <password>\nOptions are: -i, -j, -k (see assignment)";
	if (argc < 3) {
		printf("%s\n", helpstr);
		return -1;
	}

	if( access( "password.txt", F_OK ) == -1 ) {
		printf("password.txt not found; please download it and put it in this directory.\n");
		return -1;
	}

	if (strlen(argv[1]) < 2) {
		printf("%s\n", helpstr);
		return -1;
	}

	switch(argv[1][1]) {
		case 'i':
			if (argc < 4) {
				printf("%s\n", helpstr);
				break;
			}
			login1(argv[2], argv[3]);
			break;
		case 'j':
			if (argc < 4) {
				printf("%s\n", helpstr);
				break;
			}
			login2(argv[2], argv[3]);
			break;
		case 'k':
			if (argc < 4) {
				printf("%s\n", helpstr);
				break;
			}
			login3(argv[2], argv[3]);
			break;
		default:
			printf("%s\n", helpstr);
			return -1;
	}
	return 0;
}
