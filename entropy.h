/* entropy.h
 *
 * by Olivier Van Rompuy
 * 11/03/2023
 * 
 * Entropy Vault command line tool
 * 
 * */

#define PAYLOAD_SIZE 960
#define MESSAGE_SIZE 958
#define BUFFER_SIZE 1024

#define RNDBUFF 65536

void init_random();
void print_hash(unsigned char * data);
void wipe_buffer(unsigned char *buff);

long int entropy_search(unsigned char * buff, unsigned char *keystr, unsigned char *pwd, unsigned char *fname, unsigned char rounds);
long int entropy_append(unsigned char * buff, unsigned char *keystr, unsigned char *pwd, unsigned char *fname, unsigned char rounds);
long int entropy_replace(unsigned char * buff, unsigned char *keystr, unsigned char *pwd, unsigned char *fname, unsigned char rounds, long int offset);
long int entropy_erase(unsigned char * buff, unsigned char *keystr, unsigned char *pwd, unsigned char *fname, unsigned char rounds, long int offset);
