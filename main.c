/* main.c
 *
 * by Olivier Van Rompuy
 * 11/03/2023
 * 
 * Entropy Vault command line tool
 * 
 * Entropy vaults are cryptographically obscured files intended to store passwords and
 * other sensitive short strings. Every entry is stored as an encrypted entry that contains payload+hash.
 * To retrieve it the program must decrypt every possible entry in the "entropy vault file" to retrieve it.
 * 
 * Meaning of entropy from Wikipedia =
 * "Entropy is a scientific concept, as well as a measurable physical property,
 *  that is most commonly associated with a state of disorder, randomness, or uncertainty."
 * 
 * The vault files are stored in ${HOME}/.entropy
 * 
 * */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>
#include <time.h>
#include <dirent.h>

#include "entropy.h"

#define DEFAULT_ROUNDS 3

int main(int argc, char **argv)
{
 unsigned char badsyntax=0;
 unsigned char mode=0;   //0=query,1=append,2=replace,3=erase
 unsigned char imode=0;  //input mode 0=stdin, 1=password prompt
 unsigned char syscmd=0; //0=display string,1=execute as script
 unsigned char distype=0; //0=printed as hidden string,1=print full string
 unsigned char *opt, * cmd=*argv, *c;
 unsigned char basepath[256]={0};
 unsigned char filepath[512]={0};
 unsigned char keystring[256]={0};
 unsigned char password[256]={0};
 unsigned char prompt[256]={0};
 unsigned char payload[PAYLOAD_SIZE+1]={0};
 unsigned char check[PAYLOAD_SIZE+1]={0};
 unsigned char buffer[BUFFER_SIZE]={0};
 unsigned char rounds=DEFAULT_ROUNDS;
 long int offset=0,rr=0;
 int len,rc;
 DIR *dp;
 struct dirent *entry;
 snprintf(basepath,256,"%s/.pwvlt", getpwuid(getuid())->pw_dir);
 snprintf(filepath,256,"%s/.default.entropy",basepath); 

 //Option handling
 argc--;
 argv++;

 while (argc>1) {
  opt=*argv;
  if (*opt!='-') {badsyntax=1; argc=0;}
  else {
   switch(opt[1]) {
    case 's':
           distype=1;
           break;;
    case 'c':
           syscmd=1;
           break;
    case 'q':
           imode=1;
           break;
    case 'a':
           mode=1;
           break;
    case 'r':
           mode=2;
           break;
    case 'e':
           mode=3;
           break;
    case 'v':
           argc--;
           argv++;
           if (argc>0) {snprintf(filepath,256,"%s/.%s.entropy",basepath,argv[0]);}
           else {badsyntax=1;}
           break;
    case 'p':
           argc--;
           argv++;
           if (argc>0) {snprintf(password,256,"%s",argv[0]);}
           else {badsyntax=1;}
           break;
    case '%':
           argc--;
           argv++;
           if (argc>0) {rounds=atoi(argv[0]);}
           else {badsyntax=1;}
           break;
    default:
           badsyntax=1;
           break;
   }
   argc--;
   argv++;
  }
 }

 if (argc>0) {
  opt=*argv;
  if (opt[0]=='-' && opt[1]=='l') {
    mode=9;
  } else {
    strncpy(keystring,argv[0],256);
    keystring[255]=0;
  }
 } else {
    badsyntax=1;
 }

// Bad or empty options -> Display help
 if (badsyntax)
 {
    fprintf(stderr,"%s -> Password & String Vault\n by Olivier Van Rompuy\n\n",cmd);
    fprintf(stderr,"Search Entry  : %s [-s] [-c] [-p vault_password] [-v vault_name] [-%% rounds] keystring\n",cmd);
    fprintf(stderr,"Append Entry  : %s -a [-q] [-p vault_password] [-v vault_name] [-%% rounds] keystring\n",cmd);
    fprintf(stderr,"Replace Entry : %s -r [-q] [-p vault_password] [-v vault_name] [-%% rounds] keystring\n",cmd);
    fprintf(stderr,"Erase Entry   : %s -e [-q] [-p vault_password] [-v vault_name] [-%% rounds] keystring\n",cmd);
    fprintf(stderr,"List Vaults   : %s -l\n\n",cmd);
    fprintf(stderr,"Options\n -s \t\tOutput string in plain text instead of invisible.\n");
    fprintf(stderr," -a\t\tAppend entry\n -r\t\tReplace entry. If not found append\n -e\t\tErase entry\n -p\t\tVault password\n");
    fprintf(stderr," -q\t\tPassword type payload entry\n -v\t\tVault name\n -%%\t\tEncryption rounds\n -l\t\tList vaults\n");
    fprintf(stderr," -c\t\tExecute content as system commands\n\n");
    return -1;
 }

 //Create the .entropy path
 mkdir(basepath,S_IRWXU);

 //Enter the vault password
 if (*password==0 && mode<8) {
  if (mode==1) {
   snprintf(prompt,256,"Enter vault password for %s - 1st : ",keystring);
   strncpy(password,(unsigned char*)getpass(prompt),80);
   snprintf(prompt,256,"Enter vault password for %s - 2nd : ",keystring);
   strncpy(check   ,(unsigned char*)getpass(prompt),80);
   if (strncmp(password,check,256)!=0) {
     fprintf(stderr,"-> Error : Password entry is not identical!\n");
   }
  } else {
   snprintf(prompt,256,"Enter vault password for %s :",keystring);
   strncpy(password,(unsigned char*)getpass(prompt),80);
  }
 }

 switch(mode) {
    case 0:   //Search entry and output content
      offset=entropy_search(buffer,keystring,password,filepath,rounds);
      if (offset>-1) {
      strncpy(payload,buffer,PAYLOAD_SIZE);
      payload[PAYLOAD_SIZE]=0;
      if (syscmd) {
       rc=system(payload);
      } else {
       if (distype==0) fprintf(stdout,"Copy/Paste between >>>%c[8m",27);
       fwrite(payload,1,strnlen(payload,PAYLOAD_SIZE),stdout);
       if (distype==0) fprintf(stdout,"%c[m<<<",27);
      }
      }
     break;
    case 1:   //Append entry
       if (imode==1) {
        strncpy(payload,(unsigned char*)getpass("Payload 1st : "),80);
        strncpy(check  ,(unsigned char*)getpass("Payload 2nd : "),80);
       if (strncmp(payload,check,PAYLOAD_SIZE+1)!=0) {
        fprintf(stderr,"-> Error : Payload entry is not identical!\n");
        return -2;
       }
       } else {
        rr=fread(payload,1,PAYLOAD_SIZE,stdin);
       }
      wipe_buffer(buffer);
      strncpy(buffer,payload,PAYLOAD_SIZE);
      entropy_append(buffer,keystring,password,filepath,rounds);
     break;
    case 2:   //Replace entry
       offset=entropy_search(buffer,keystring,password,filepath,rounds);
       
       strncpy(payload,buffer,PAYLOAD_SIZE);
       payload[PAYLOAD_SIZE]=0;

       if (imode==1) {
        strncpy(payload,(unsigned char*)getpass("Payload 1st : "),80);
        strncpy(check  ,(unsigned char*)getpass("Payload 2nd : "),80);
       if (strncmp(payload,check,PAYLOAD_SIZE+1)!=0) {
        fprintf(stderr,"-> Error : Payload entry is not identical!\n");
        return -2;
       }
       } else {
        rr=fread(payload,1,PAYLOAD_SIZE,stdin);
	payload[rr]=0;
       }

       wipe_buffer(buffer);
       strncpy(buffer,payload,PAYLOAD_SIZE);

       //Replace the entry of found, otherwise append.
       if (offset>-1) {
        entropy_replace(buffer,keystring,password,filepath,rounds,offset);
       } else {
        entropy_append(buffer,keystring,password,filepath,rounds);
        return -5;
       }
     break;
    case 3:  //Erase entry
       offset=entropy_search(buffer,keystring,password,filepath,rounds);
       if (offset>-1) {
        strncpy(payload,buffer,PAYLOAD_SIZE);
        payload[PAYLOAD_SIZE]=0;
        wipe_buffer(buffer);
        buffer[0]=0;
        entropy_erase(buffer,keystring,password,filepath,rounds,offset);
       } else {
        fprintf(stderr," Error : Keystring entry not found!\n");
        return -5;
       }
     break;
    case 9:
       dp=opendir(basepath);
       if (dp==NULL) {
              return -6;
       }
       while (entry=readdir(dp)) {
              strncpy(check,entry->d_name,64);
              len=strnlen(check,64);
              if (len>9 && *check=='.') {
                     c=check+len-8;
                     if (strncmp(c,".entropy",8)==0) {
                      *c=0;
                      c=check+1;
                      puts(c);
                     }
              }
       }
       closedir(dp);
     break;
 }
 fflush(stdout);
 fprintf(stderr,"\n");
 return 0;
}
