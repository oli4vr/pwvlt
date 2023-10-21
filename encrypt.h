/* encrypt.h
 *
 * by Olivier Van Rompuy
 *
 */

typedef struct _crypttale {
 unsigned char key[1024];
 unsigned char ttable[256][256];
 unsigned char dtable[256][256];
 int rounds;
} crypttale;

int init_encrypt(crypttale * ct,unsigned char * keystr,int nr_rounds);
int encrypt_data(crypttale * ct,unsigned char * buffer,int len);
int decrypt_data(crypttale * ct,unsigned char * buffer,int len);

