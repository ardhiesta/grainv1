#include <stdio.h>
#include "grain.h"
#include <string.h>
#include <stdlib.h>

/*
 * Function: grain_keystream
 *
 * Synopsis
 *  Generates a new bit and updates the internal state of the cipher.
 */

int grain_keystream(grain* mygrain) {
	int i,NBit,LBit,outbit;
	/* Calculate feedback and output bits */
	outbit = N(79)^N(78)^N(76)^N(70)^N(49)^N(37)^N(24) ^ X1 ^ X4 ^ X0&X3 ^ X2&X3 ^ X3&X4 ^ X0&X1&X2 ^ X0&X2&X3 ^ X0&X2&X4 ^ X1&X2&X4 ^ X2&X3&X4;

	NBit=L(80)^N(18)^N(20)^N(28)^N(35)^N(43)^N(47)^N(52)^N(59)^N(66)^N(71)^N(80)^
			N(17)&N(20) ^ N(43)&N(47) ^ N(65)&N(71) ^ N(20)&N(28)&N(35) ^ N(47)&N(52)&N(59) ^ N(17)&N(35)&N(52)&N(71)^
			N(20)&N(28)&N(43)&N(47) ^ N(17)&N(20)&N(59)&N(65) ^ N(17)&N(20)&N(28)&N(35)&N(43) ^ N(47)&N(52)&N(59)&N(65)&N(71)^
			N(28)&N(35)&N(43)&N(47)&N(52)&N(59);
	LBit=L(18)^L(29)^L(42)^L(57)^L(67)^L(80);
	/* Update registers */
	for (i=1;i<(mygrain->keysize);++i) {
		mygrain->NFSR[i-1]=mygrain->NFSR[i];
		mygrain->LFSR[i-1]=mygrain->LFSR[i];
	}
	mygrain->NFSR[(mygrain->keysize)-1]=NBit;
	mygrain->LFSR[(mygrain->keysize)-1]=LBit;
	return outbit;
}

/*
 * Function: keystream_bytes
 *
 * Synopsis
 *  Generate keystream in bytes.
 *
 * Assumptions
 *  Bits are generated in order z0,z1,z2,...
 *  The bits are stored in a byte in order:
 *
 *  lsb of keystream[0] = z0
 *  ...
 *  msb of keystream[0] = z7
 *  ...
 *  lsb of keystream[1] = z8
 *  ...
 *  msb of keystream[1] = z15
 *  ...
 *  ...
 *  ...
 *  Example: The bit keystream: 10011100 10110011 ..
 *  corresponds to the byte keystream: 39 cd ..
 */
void keystream_bytes(
  grain* mygrain,
  int* keystream,
  int msglen)
{
	int i,j;
	for (i = 0; i < msglen; ++i) {
		keystream[i]=0;
		for (j = 0; j < 8; ++j) {
			keystream[i]|=(grain_keystream(mygrain)<<j);
		}
	}
}

void keysetup(
  grain* mygrain,
  const int* key,
  int keysize,			/* Key size in bits. */
  int ivsize)			/* IV size in bits. */
{
	mygrain->p_key=key;
	mygrain->keysize=keysize;
	mygrain->ivsize=ivsize;
}

/*
 * Function: ivsetup
 *
 * Synopsis
 *  Load the key and perform initial clockings.
 *
 * Assumptions
 *  The key is 10 bytes and the IV is 8 bytes. The
 *  registers are loaded in the following way:
 *
 *  NFSR[0] = lsb of key[0]
 *  ...
 *  NFSR[7] = msb of key[0]
 *  ...
 *  ...
 *  NFSR[72] = lsb of key[9]
 *  ...
 *  NFSR[79] = msb of key[9]
 *  LFSR[0] = lsb of IV[0]
 *  ...
 *  LFSR[7] = msb of IV[0]
 *  ...
 *  ...
 *  LFSR[56] = lsb of IV[7]
 *  ...
 *  LFSR[63] = msb of IV[7]
 */
void ivsetup(
  grain* mygrain,
  const int* iv)
{
	int i,j;
	int outbit;
	/* load registers */
	for (i=0;i<(mygrain->ivsize)/8;++i) {
		for (j=0;j<8;++j) {
			mygrain->NFSR[i*8+j]=((mygrain->p_key[i]>>j)&1);
			mygrain->LFSR[i*8+j]=((iv[i]>>j)&1);
		}
	}
	for (i=(mygrain->ivsize)/8;i<(mygrain->keysize)/8;++i) {
		for (j=0;j<8;++j) {
			mygrain->NFSR[i*8+j]=((mygrain->p_key[i]>>j)&1);
			mygrain->LFSR[i*8+j]=1;
		}
	}
	/* do initial clockings */
	for (i=0;i<INITCLOCKS;++i) {
		outbit=grain_keystream(mygrain);
		/*printf("%d",(int)outbit);*/
		mygrain->LFSR[79]^=outbit;  /* LFSR[79] = LFSR[79] ^ outbit */
		mygrain->NFSR[79]^=outbit;  /* NFSR[79] = NFSR[79] ^ outbit */
	}
}

void encrypt_bytes(
  grain* mygrain,
  const int* plaintext,
  int* ciphertext,
  int msglen)
{
	int i,j;
	int k;
	for (i = 0; i < msglen; ++i) {
		k=0;
		for (j = 0; j < 8; ++j) {
			k|=(grain_keystream(mygrain)<<j);
		}
		ciphertext[i]=plaintext[i]^k;
	}
}

void decrypt_bytes(
  grain* mygrain,
  const int* ciphertext,
  int* plaintext,
  int msglen)
{
	int i,j;
	int k=0;
	for (i = 0; i < msglen; ++i) {
		k=0;
		for (j = 0; j < 8; ++j) {
			k|=(grain_keystream(mygrain)<<j);
		}
		plaintext[i]=ciphertext[i]^k;
	}
}

/*  GENERATE TEST VECTORS  */

void printData(int *key, int *IV, int *ks, int *pt, int *et, int *dt, int sizeOfPlaintext) {
	int i;
	printf("\nkey            : ");
	for (i=0;i<10;++i) printf("%02x ",(int)key[i]);
	printf("\nIV             : ");
	for (i=0;i<8;++i) printf("%02x ",(int)IV[i]);
	printf("\nkeystream      : ");
	for (i=0;i<10;++i) printf("%02x ",(int)ks[i]);
	printf("\nplaintext      : ");
	for (i=0;i<sizeOfPlaintext;i++) printf("%02x ",(int)pt[i]);
	printf("\nencrypted text : ");
    for (i=0;i<sizeOfPlaintext;i++) printf("%02X ",(int)et[i]);
	printf("\ndecrypted text : ");
	for (i=0;i<sizeOfPlaintext;i++) printf("%02x ",(int)dt[i]); printf("\n");
}

int* convertToHexInt(int *result, char *str) {

    for (int i = 0; i < strlen(str); i++)
    {
        char temp[5] = "";
        sprintf(temp, "%#02X", str[i]);
        int number = (int)strtol(temp, NULL, 0);
        result[i] = number;
    }
   
    return result;
}

int main() {
  // int plaintext[10]={0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01};
  int sizeOfPlaintext=8; //fill size here
	int encrypted_text[8];
	int decrypted_text[8];

  grain mygrain;

  int /*key1[10] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},*/
		  IV1[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
	    ks[10];

  	 char key[10] = "syafa123"; //kunci 
     char text[8]; 
    sprintf(text, "%.2f", 22.0);

    char result[256];
    
    strcat(text, ";");
    strcat(text, result);
  
  int resultKey[8];
  int resultText[8];
  int* key1 = convertToHexInt(resultKey, key); //mengubah key menjadi bilangan hex
  int* plaintext = convertToHexInt(resultText, text); 
//   plaintext = 22.00;00 (kode ascii dalam hex - 32 st)
//   text = 22.00;00 (kode ascii desimal - 50 dst)
// convertToHexInt : mengubah dari ascii kode desimal ke ascii kode hex

  keysetup(&mygrain,key1,80,64);
	ivsetup(&mygrain,IV1);
	keystream_bytes(&mygrain,ks,8);
	grain mygrain2 = mygrain;
	encrypt_bytes(&mygrain,plaintext,encrypted_text,8);
	decrypt_bytes(&mygrain2,encrypted_text,decrypted_text,8);
	printData(key1,IV1,ks, plaintext, encrypted_text, decrypted_text, 8);

  /*
73 79 61 66 61 31 32 33 32 32
s  y  a  f  a  1  2  3  2  2

32 32 2e 30 30 3b 00 00
2  2  .  0  0  ;  

encrypted
A5 2E A7 59 FC FA 39 2C

key            : 73 79 61 66 61 31 32 33 32 32 
IV             : 00 00 00 00 00 00 00 00 
keystream      : 4d 7f 03 e0 35 6e 9c a9 00 00 
plaintext      : 32 32 2e 30 30 3b 00 00 
encrypted text : A5 2E A7 59 FC FA 39 2C 
decrypted text : 32 32 2e 30 30 3b 00 00 
  */

  return 0;
}
