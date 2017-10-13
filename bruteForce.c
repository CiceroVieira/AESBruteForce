#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#include <openssl/aes.h>

void testaCorretude()
{
	unsigned char key[] = "essasenhaehfraca";
	AES_KEY aes_key;
	AES_KEY aes_dkey;

	unsigned char claro[16] = "Texto para teste";
	unsigned char cifrado[sizeof(claro)];
	unsigned char decifrado[sizeof(claro)];

	printf("%d\n", sizeof(claro));

	AES_set_encrypt_key(key, 128, &aes_key);
	AES_ecb_encrypt(claro, cifrado, &aes_key, AES_ENCRYPT);

	for (int i=0; i<AES_BLOCK_SIZE; i++)
	{
        printf("%x ", cifrado[i]);
	}
    printf("\n");

    for (int i=0; i<AES_BLOCK_SIZE; i++)
	{
        printf("%c ", cifrado[i]);
	}

    printf("\n");

    for (int i=0; i<AES_BLOCK_SIZE; i++)
	{
        printf("%d ", cifrado[i]);
	}
    printf("\n");

    AES_set_decrypt_key(key, 128, &aes_dkey);
    AES_ecb_encrypt(cifrado, decifrado, &aes_dkey, AES_DECRYPT);

    for (int i=0; i<AES_BLOCK_SIZE; i++)
	{
        printf("%c", decifrado[i]);
	}

    printf("\n");

}

void printDec(unsigned char* buffer, int size)
{
	for (int i=0; i<size; i++)
	{
        printf("%d ", buffer[i]);
	}
    printf("\n");
}
/*
int verifica(unsigned char* teste, int mSIZE) 
{
	int encontrouCharErrado = 0;

	for (int i=0; i<mSIZE; i++)
	{
        for (int e=0; e<=31; e++)
        {
        	if (teste[i] == 9 || teste[i] == 10 || teste[i] == 13 || teste[i] == 0)
        	{
        		continue;
        	}
        	if (teste[i] == e) {
        		encontrouCharErrado = 1;
        		return -1;
        	}
        }
	}

	return 1;
}*/

int verifica(unsigned char* candidato, int mSIZE){
	int encontrouCharErrado = 0;
	for(int i=0; i<mSIZE; i++){
		if(candidato[i] <= 31){
			if(!(candidato[i]==0 || candidato[i] == 9 || candidato[i] == 10 || candidato[i] == 11 || candidato[i] == 13))
				return -1;
		}
	}
	return 1;
}

void print2(unsigned char* buffer, int size)
{
	for (int i=0; i<size; i++)
	{
        printf("%lc", buffer[i]);
	}
    printf("\n");
}

void print3(unsigned char* buffer, int size)
{
	for (int i=0; i<size; i++)
	{
        printf("%d ", buffer[i]);
	}
    printf("\n");
}


void *bruteForce2(int x)
{
	//printf("Aqui\n");
	char filename[100];
	sprintf(filename, "results_%d.txt\0", x);


	FILE *fp = fopen(filename, "w");

	//printf("Aqui\n");

	time_t rawtime;
	struct tm * timeinfo;

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	fwrite(asctime(timeinfo), sizeof(char), sizeof(asctime(timeinfo)), fp);

	
	int mSIZEkey = 16;
	int inicMulti, fimMulti;
	

	/*
	int mSIZE = 17;
	unsigned char claro[mSIZE] = "Texto para téste";
	unsigned char cifrado[mSIZE];
	unsigned char key[17] = "Key2Group17";
	key[11] = 33;
	key[12] = 33;
	key[13] = 33;
	key[14] = 34;
	key[15] = 33;
	AES_KEY aes_key;
	AES_set_encrypt_key(key, 128, &aes_key);
	AES_ecb_encrypt(claro, cifrado, &aes_key, AES_ENCRYPT);
	*/


	//int mSIZE = (AES_BLOCK_SIZE * 42) + 1;
	//unsigned char cifrado[mSIZE] = "5D80B22B7AE8ECD2FE85DB34AF46436069F1959B24998C569078BDB9B137E7B7C098A1866273C219EAAF296B68EE224565A3D704BDEC51638A880002DC6188A97D007FD1D4F58C2794017272433F7235C31344841374F957485B39AA8D3DF4A2C6DE4332405BE51C065D38106840674C775C343D8068C5AEE95327B57DF0955C4C8B340B5C9848540DCD0494BAAB2ABBDC8D4D92105F757C02B6BB3189298BE172FF4D6B40435134FC677047C44D440C3D8D5E62FD8A2340085C93AFC53EF733FBA235553C89CCDFF3D478BAF467D3F15859643DF3CD2BFA74A561F8A8F822AE8FF5F3827BBA50AFC39CB2E390CAC23A2A9A291072E21186D5E144CAB7B3FE06EB0D68B27D5BD8E0A2EA37AD3AEC4F1E657264F53D53C45C81DFD9DAE9A8B1F3606E229B6F3DB0EC43949101110E7667AB33A862B82C5CB44694224099E2C8AA63704ACCDB22CDCE266B636CC400485C";

	unsigned char cifrado[] = {0x5D, 0x80, 0xB2, 0x2B, 0x7A, 0xE8, 0xEC, 0xD2, 0xFE, 0x85, 0xDB, 0x34, 0xAF, 0x46, 0x43, 0x60, 0x69, 0xF1, 0x95, 0x9B, 0x24, 0x99, 0x8C, 0x56, 0x90, 0x78, 0xBD, 0xB9, 0xB1, 0x37, 0xE7, 0xB7, 0xC0, 0x98, 0xA1, 0x86, 0x62, 0x73, 0xC2, 0x19, 0xEA, 0xAF, 0x29, 0x6B, 0x68, 0xEE, 0x22, 0x45, 0x65, 0xA3, 0xD7, 0x04, 0xBD, 0xEC, 0x51, 0x63, 0x8A, 0x88, 0x00, 0x02, 0xDC, 0x61, 0x88, 0xA9, 0x7D, 0x00, 0x7F, 0xD1, 0xD4, 0xF5, 0x8C, 0x27, 0x94, 0x01, 0x72, 0x72, 0x43, 0x3F, 0x72, 0x35, 0xC3, 0x13, 0x44, 0x84, 0x13, 0x74, 0xF9, 0x57, 0x48, 0x5B, 0x39, 0xAA, 0x8D, 0x3D, 0xF4, 0xA2, 0xC6, 0xDE, 0x43, 0x32, 0x40, 0x5B, 0xE5, 0x1C, 0x06, 0x5D, 0x38, 0x10, 0x68, 0x40, 0x67, 0x4C, 0x77, 0x5C, 0x34, 0x3D, 0x80, 0x68, 0xC5, 0xAE, 0xE9, 0x53, 0x27, 0xB5, 0x7D, 0xF0, 0x95, 0x5C, 0x4C, 0x8B, 0x34, 0x0B, 0x5C, 0x98, 0x48, 0x54, 0x0D, 0xCD, 0x04, 0x94, 0xBA, 0xAB, 0x2A, 0xBB, 0xDC, 0x8D, 0x4D, 0x92, 0x10, 0x5F, 0x75, 0x7C, 0x02, 0xB6, 0xBB, 0x31, 0x89, 0x29, 0x8B, 0xE1, 0x72, 0xFF, 0x4D, 0x6B, 0x40, 0x43, 0x51, 0x34, 0xFC, 0x67, 0x70, 0x47, 0xC4, 0x4D, 0x44, 0x0C, 0x3D, 0x8D, 0x5E, 0x62, 0xFD, 0x8A, 0x23, 0x40, 0x08, 0x5C, 0x93, 0xAF, 0xC5, 0x3E, 0xF7, 0x33, 0xFB, 0xA2, 0x35, 0x55, 0x3C, 0x89, 0xCC, 0xDF, 0xF3, 0xD4, 0x78, 0xBA, 0xF4, 0x67, 0xD3, 0xF1, 0x58, 0x59, 0x64, 0x3D, 0xF3, 0xCD, 0x2B, 0xFA, 0x74, 0xA5, 0x61, 0xF8, 0xA8, 0xF8, 0x22, 0xAE, 0x8F, 0xF5, 0xF3, 0x82, 0x7B, 0xBA, 0x50, 0xAF, 0xC3, 0x9C, 0xB2, 0xE3, 0x90, 0xCA, 0xC2, 0x3A, 0x2A, 0x9A, 0x29, 0x10, 0x72, 0xE2, 0x11, 0x86, 0xD5, 0xE1, 0x44, 0xCA, 0xB7, 0xB3, 0xFE, 0x06, 0xEB, 0x0D, 0x68, 0xB2, 0x7D, 0x5B, 0xD8, 0xE0, 0xA2, 0xEA, 0x37, 0xAD, 0x3A, 0xEC, 0x4F, 0x1E, 0x65, 0x72, 0x64, 0xF5, 0x3D, 0x53, 0xC4, 0x5C, 0x81, 0xDF, 0xD9, 0xDA, 0xE9, 0xA8, 0xB1, 0xF3, 0x60, 0x6E, 0x22, 0x9B, 0x6F, 0x3D, 0xB0, 0xEC, 0x43, 0x94, 0x91, 0x01, 0x11, 0x0E, 0x76, 0x67, 0xAB, 0x33, 0xA8, 0x62, 0xB8, 0x2C, 0x5C, 0xB4, 0x46, 0x94, 0x22, 0x40, 0x99, 0xE2, 0xC8, 0xAA, 0x63, 0x70, 0x4A, 0xCC, 0xDB, 0x22, 0xCD, 0xCE, 0x26, 0x6B, 0x63, 0x6C, 0xC4, 0x00, 0x48, 0x5C};
	int mSIZE = sizeof(cifrado);


	AES_KEY aes_keytest;
	unsigned char keytest[16] = "Key2Group17";
	unsigned char teste[mSIZE];


	switch(x){
		case 1:
			inicMulti = 33;
			fimMulti = 44;
			break;
		case 2:
			inicMulti = 45;
			fimMulti = 56;
			break;
		case 3:
			inicMulti = 57;
			fimMulti = 68;
			break;
		case 4: 
			inicMulti = 69;
			fimMulti = 80;
			break;
		case 5:
			inicMulti = 81;
			fimMulti = 92;
			break;
		case 6:
			inicMulti = 93;
			fimMulti = 104;
			break;
		case 7:
			inicMulti = 105;
			fimMulti = 116;
			break;
		case 8:
			inicMulti = 117;
			fimMulti = 126;
			break;

	}
	for(int i1=inicMulti; i1<=fimMulti; i1++)
	{
	//int i1 = x;

		printf("i1 = %d\n", i1);

		keytest[11] = (char) i1;

		for(int i2=33; i2<=126; i2++)
		{
			printf("  i2 = %d\n", i2);

			keytest[12] = (char) i2;

			for(int i3=33; i3<=126; i3++)
			{
				keytest[13] = (char) i3;

				for(int i4=33; i4<=126; i4++)
				{
					keytest[14] = (char) i4;

					for(int i5=33; i5<=126; i5++)
					{
						keytest[15] = (char) i5;

						AES_set_decrypt_key(keytest, 128, &aes_keytest);
						AES_ecb_encrypt(cifrado, teste, &aes_keytest, AES_DECRYPT);

						if (verifica(teste, mSIZE) > 0) 
						{
							fwrite(keytest, sizeof(char), mSIZEkey, fp);
							fwrite("\n", sizeof(char), 1, fp);
							fwrite(teste, sizeof(char), mSIZE, fp);
							fwrite("\n\n\n", sizeof(char), 3, fp);

							time(&rawtime);
							timeinfo = localtime(&rawtime);
							fwrite(asctime(timeinfo), sizeof(char), sizeof(asctime(timeinfo)), fp);

							printf("\n\n\n---------------\n");
							printf("ACHOU!!!!\nKEY=%d %d %d %d %d\nTEXTO=\n", i1, i2, i3, i4, i5);
							print3(teste, mSIZE);
							print2(teste, mSIZE);
							printf("\n\n");

							
						}
					}
				}
			}
		}
	}
	fclose(fp);
}

int main(int argc, char *argv[])
{
	printf("Hi\n");

	int count;

	pthread_t thread[8];


	for(count = 0; count < 8; count++){
		pthread_create(&thread[count], NULL, bruteForce2, count+1);
	}

	for(count = 0; count < 8; count++)
    {
        pthread_join(thread[count], NULL);
    }



	//char *p;
	//long conv = strtol(argv[1], &p, 10);
	//int x = conv;

	//testaCorretude();
	//bruteForce2(x);

    return 0;
}