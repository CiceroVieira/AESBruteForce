##Desafio 5 - INF01045

Ataque força bruta a um texto cifrado usando AES-ECB-128.
Ataque opera com 8 threads, e foi rodado numa CPU Intel Core i7-4770HQ 2.2 GHz
Turbo Bost 3.4 GHz, Hyperthreading, AES-NI
SO: macOS 10.13
16 GB RAM
Compilado com: clang 9.0.0
Dependências: OpenSSL, pthread.
Para compilar:
gcc -o bruteF bruteForce.c -L /path/to/lcrypto/lib -I /path/to/openssl/headers -lcrypto -lpthread
