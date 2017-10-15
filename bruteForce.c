/* Ataque forca bruta AES */
/* Autores: Mauricio Ize, Airton Depauli */
/* Texto criptografado esta na linha 97. Cada numero item do vetor eh um caractere Windows-1252 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#include <openssl/aes.h>

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
int cracked = 0;

void testaCorretude(){
	unsigned char key[] = "essasenhaehfraca";
	AES_KEY aes_key, aes_dkey;

	unsigned char claro[] = "Texto para teste";
	unsigned char cifrado[sizeof(claro)];
	unsigned char decifrado[sizeof(claro)];

	AES_set_encrypt_key(key, 128, &aes_key);
	AES_ecb_encrypt(claro, cifrado, &aes_key, AES_ENCRYPT);

	for (int i=0; i<AES_BLOCK_SIZE; i++){
        printf("%x ", cifrado[i]);
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

void print3(unsigned char* buffer, int size)
{
	for (int i=0; i<size; i++)
	{
        printf("%02X", buffer[i]);
	}
    printf("\n");
    for (int i=0; i<size; i++)
	{
        printf("%03d ", buffer[i]);
	}
	printf("\n");
	for (int i=0; i<size; i++)
	{
        printf("%c ", buffer[i]);
	}
    printf("\n\n\n");
}

void print2(unsigned char* buffer, int size)
{
	for (int i=0; i<size; i++)
	{
        printf("%lc", buffer[i]);
	}
    printf("\n");
}

int verifica(unsigned char* candidato, int mSIZE){
	int encontrouCharErrado = 0;
	for(int i=0; i<mSIZE; i++){
		if(candidato[i] <= 31){
			if(!(candidato[i]==0 || candidato[i] == 9 || candidato[i] == 10 || candidato[i] == 11 || candidato[i] == 13))
				return 0;
		}
	}
	return 1;
}

void *bruteForceAttack(int ThreadN){
	char filename[100];

	sprintf(filename, "results_%d.txt\0", ThreadN);
	FILE *fp = fopen(filename, "w");

	////////////////////////////////// Escreve Hora de inicio no arquivo /////////////////////////////
	char buff[20];
    struct tm *sTm;

    time_t now = time (0);
    sTm = gmtime (&now);

    strftime (buff, sizeof(buff), "%Y-%m-%d %H:%M:%S", sTm);

    fwrite(buff, sizeof(char), sizeof(buff), fp);

    //////////////////////////////////////////////////////////////

	int mSizeKey = 16;
	int beginSearch, endSearch;

	int KEY_SIZE = 16;

	unsigned char cifrado[] = {0x5D, 0x80, 0xB2, 0x2B, 0x7A, 0xE8, 0xEC, 0xD2, 0xFE, 0x85, 0xDB, 0x34, 0xAF, 0x46, 0x43, 0x60, 0x69, 0xF1, 0x95, 0x9B, 0x24, 0x99, 0x8C, 0x56, 0x90, 0x78, 0xBD, 0xB9, 0xB1, 0x37, 0xE7, 0xB7, 0xC0, 0x98, 0xA1, 0x86, 0x62, 0x73, 0xC2, 0x19, 0xEA, 0xAF, 0x29, 0x6B, 0x68, 0xEE, 0x22, 0x45, 0x65, 0xA3, 0xD7, 0x04, 0xBD, 0xEC, 0x51, 0x63, 0x8A, 0x88, 0x00, 0x02, 0xDC, 0x61, 0x88, 0xA9, 0x7D, 0x00, 0x7F, 0xD1, 0xD4, 0xF5, 0x8C, 0x27, 0x94, 0x01, 0x72, 0x72, 0x43, 0x3F, 0x72, 0x35, 0xC3, 0x13, 0x44, 0x84, 0x13, 0x74, 0xF9, 0x57, 0x48, 0x5B, 0x39, 0xAA, 0x8D, 0x3D, 0xF4, 0xA2, 0xC6, 0xDE, 0x43, 0x32, 0x40, 0x5B, 0xE5, 0x1C, 0x06, 0x5D, 0x38, 0x10, 0x68, 0x40, 0x67, 0x4C, 0x77, 0x5C, 0x34, 0x3D, 0x80, 0x68, 0xC5, 0xAE, 0xE9, 0x53, 0x27, 0xB5, 0x7D, 0xF0, 0x95, 0x5C, 0x4C, 0x8B, 0x34, 0x0B, 0x5C, 0x98, 0x48, 0x54, 0x0D, 0xCD, 0x04, 0x94, 0xBA, 0xAB, 0x2A, 0xBB, 0xDC, 0x8D, 0x4D, 0x92, 0x10, 0x5F, 0x75, 0x7C, 0x02, 0xB6, 0xBB, 0x31, 0x89, 0x29, 0x8B, 0xE1, 0x72, 0xFF, 0x4D, 0x6B, 0x40, 0x43, 0x51, 0x34, 0xFC, 0x67, 0x70, 0x47, 0xC4, 0x4D, 0x44, 0x0C, 0x3D, 0x8D, 0x5E, 0x62, 0xFD, 0x8A, 0x23, 0x40, 0x08, 0x5C, 0x93, 0xAF, 0xC5, 0x3E, 0xF7, 0x33, 0xFB, 0xA2, 0x35, 0x55, 0x3C, 0x89, 0xCC, 0xDF, 0xF3, 0xD4, 0x78, 0xBA, 0xF4, 0x67, 0xD3, 0xF1, 0x58, 0x59, 0x64, 0x3D, 0xF3, 0xCD, 0x2B, 0xFA, 0x74, 0xA5, 0x61, 0xF8, 0xA8, 0xF8, 0x22, 0xAE, 0x8F, 0xF5, 0xF3, 0x82, 0x7B, 0xBA, 0x50, 0xAF, 0xC3, 0x9C, 0xB2, 0xE3, 0x90, 0xCA, 0xC2, 0x3A, 0x2A, 0x9A, 0x29, 0x10, 0x72, 0xE2, 0x11, 0x86, 0xD5, 0xE1, 0x44, 0xCA, 0xB7, 0xB3, 0xFE, 0x06, 0xEB, 0x0D, 0x68, 0xB2, 0x7D, 0x5B, 0xD8, 0xE0, 0xA2, 0xEA, 0x37, 0xAD, 0x3A, 0xEC, 0x4F, 0x1E, 0x65, 0x72, 0x64, 0xF5, 0x3D, 0x53, 0xC4, 0x5C, 0x81, 0xDF, 0xD9, 0xDA, 0xE9, 0xA8, 0xB1, 0xF3, 0x60, 0x6E, 0x22, 0x9B, 0x6F, 0x3D, 0xB0, 0xEC, 0x43, 0x94, 0x91, 0x01, 0x11, 0x0E, 0x76, 0x67, 0xAB, 0x33, 0xA8, 0x62, 0xB8, 0x2C, 0x5C, 0xB4, 0x46, 0x94, 0x22, 0x40, 0x99, 0xE2, 0xC8, 0xAA, 0x63, 0x70, 0x4A, 0xCC, 0xDB, 0x22, 0xCD, 0xCE, 0x26, 0x6B, 0x63, 0x6C, 0xC4, 0x00, 0x48, 0x5C};
	int mSIZE = sizeof(cifrado);

	AES_KEY aes_keytest;

	unsigned char keytest[16] = "Key2Group17!!!!!";
	unsigned char *blocos[21];

	unsigned char blocoDecifrar[16];
	unsigned char bloco_claro[16];

	for(int linha=0; linha<21; linha++){
		blocos[linha] = &cifrado[linha*16];
	}

	switch(ThreadN){
		case 1:
			beginSearch = 33;
			endSearch = 44;
			break;
		case 2:
			beginSearch = 45;
			endSearch = 56;
			break;
		case 3:
			beginSearch = 57;
			endSearch = 68;
			break;
		case 4:
			beginSearch = 69;
			endSearch = 80;
			break;
		case 5:
			beginSearch = 81;
			endSearch = 92;
			break;
		case 6:
			beginSearch = 93;
			endSearch = 104;
			break;
		case 7:
			beginSearch = 105;
			endSearch = 116;
			break;
		case 8:
			beginSearch = 117;
			endSearch = 126;
			break;

	}
	int c1, c2, c3, c4, c5;
	int condCheck;
	for(c1=beginSearch; c1<=endSearch; c1++){
		printf("c1 = %d\n", c1);
		keytest[11] = (unsigned char) c1;
		pthread_mutex_lock(&lock);
		condCheck = cracked;
		pthread_mutex_unlock(&lock);
		if(condCheck != 0){
			fclose(fp);
			pthread_exit(NULL);
		}
		else{
			for(c2=33; c2<=126; c2++){
				keytest[12] = (unsigned char) c2;
				for(c3=33; c3<=126; c3++){
					keytest[13] = (unsigned char) c3;
					for(c4=33; c4<=126; c4++){
						keytest[14] = (unsigned char) c4;
						for(c5=33; c5<=126; c5++){
							keytest[15] = (unsigned char) c5;
	
							//unsigned char bloco_claro[16];
	
							int passou=1;
	
							//AES_KEY aes_keytest;
	
							AES_set_decrypt_key(keytest, 128, &aes_keytest);
	
							for(int blocoAtual = 0; blocoAtual<21; blocoAtual++){
	
								memcpy(blocoDecifrar, blocos[blocoAtual], 16);
								AES_ecb_encrypt(blocoDecifrar, bloco_claro, &aes_keytest, AES_DECRYPT);
	
								int mVerifica = verifica(bloco_claro, 16);
	
								if(mVerifica == 0){
									passou = 0;
									break;
								}
							}
	
							if(passou == 1){
								fwrite(keytest, sizeof(unsigned char), KEY_SIZE, fp);
								fwrite("\n", sizeof(unsigned char), 1, fp);
								fwrite(bloco_claro, sizeof(unsigned char), 16, fp);
								fwrite("\n\n\n", sizeof(unsigned char), 3, fp);
	
								printf("\n\n------------------------------ ACHOU:\n\n");
								printf("KEY=%d %d %d %d %d \nTEXTO= \n", c1, c2, c3, c4, c5);
								print3(bloco_claro, 16);
								printf("\n\n");
								print2(bloco_claro, 16);
								printf("\n\n------------------------------ fim\n\n");

								///////////////////////////////////Hora que achou///////////////////
								now = time (0);
    							sTm = gmtime (&now);

    							strftime (buff, sizeof(buff), "%Y-%m-%d %H:%M:%S", sTm);

    							fwrite(buff, sizeof(char), sizeof(buff), fp);

								////////////////////////////////////////////////////////////////////
	
								fclose(fp);
								pthread_mutex_lock(&lock);
								cracked = ThreadN;
								pthread_mutex_unlock(&lock);
								pthread_exit(NULL);
							}
						}
					}
				}
			}
		}
	}

	/*
	unsigned char bloco_claro[16];
	memcpy(bloco_claro, blocos[0], 16);
	for(int i=0; i<16; i++){
		printf("%x  ", bloco_claro[i]);
	}*/

	//printf("%s\n", aes_key);


	/*
	for(int linha=0; linha<21; linha++){
		for(int ind=0; ind<16; ind++){
			printf("%x\n", *(blocos[linha]+ind));
		}
		printf("\n");
	}
	*/


	fclose(fp);
	return NULL;
}

int main(){

	pthread_t thread[8];
	//testaCorretude();

	int count;

	for(count = 0; count < 8; count++){
		pthread_create(&thread[count], NULL, bruteForceAttack, count+1);
	}

	for(count = 0; count < 8; count++)
    {
        pthread_join(thread[count], NULL);
    }
	//bruteForceAttack(5);

	return 0;
}
