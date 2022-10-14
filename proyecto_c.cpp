#include "header.h" //Encabezado con todos los encabezados
#include "colores.h" //Encabezado que incluye los colores
#include "x86intrin.h" //Encabezado para OpenSSL
#pragma intrinsic(__rdtsc)
#define NTEST 100000


int main(){
    setlocale(LC_ALL, "");  //Ver acentos y ñ
    int menup, mlen;
    string x, y, doc, dockey, save, vacio, ubi,deci;
    const char* key;
    const char* deci2;
    unsigned char* c;
    unsigned char* n;
    unsigned char* k;
    c = (unsigned char*)malloc(crypto_stream_chacha20_NONCEBYTES); //NONCEBYTES regresa el numero aleatorio en bytes
    n = (unsigned char*)malloc(crypto_stream_chacha20_NONCEBYTES);
    randombytes_buf(n, crypto_stream_chacha20_NONCEBYTES); //NONCEBYTES regresa el numero aleatorio en bytes
    k = (unsigned char*)malloc(crypto_stream_chacha20_KEYBYTES); //KEYBYTES regresa el tamaño de la llave en bytes
    //Variables para la firma 
    unsigned char client_pk[crypto_kx_PUBLICKEYBYTES], client_sk[crypto_kx_SECRETKEYBYTES];
    unsigned char client_rx[crypto_kx_SESSIONKEYBYTES], client_tx[crypto_kx_SESSIONKEYBYTES];
    unsigned char server_pk[crypto_kx_PUBLICKEYBYTES], server_sk[crypto_kx_SECRETKEYBYTES];
    unsigned char server_rx[crypto_kx_SESSIONKEYBYTES], server_tx[crypto_kx_SESSIONKEYBYTES];
    crypto_kx_keypair(client_pk, client_sk);
    crypto_kx_keypair(server_pk, server_sk);

    do {
        printf(ANSI_COLOR_GREEN "\n\n\t\t\tBIENVENIDO AL SOFTWARE DE PROTECCIÓN DE DOCUMENTOS\n" ANSI_RESET_ALL);
        printf(ANSI_COLOR_GREEN "\t\t\t--------------------------------------------------\n" ANSI_RESET_ALL);
        printf("\n\t1. Generación y Recuperación de Claves\n");
        printf("\t2. Cifrado de Archivos\n");
        printf("\t3. Descifrado de Archivos\n");
        printf("\t4. Firma de Archivos\n");
        printf("\t5. Verificación de Firma de Archivos\n");
        printf("\t6. SALIR\n");
        printf(ANSI_COLOR_RED "\n\t¡Recuerda primero subir tu archivo!" ANSI_RESET_ALL);
        printf("\n\tIngresa la opción que deseas ejecutar (1-6): ");
        scanf_s("%d", &menup);

        switch (menup) {
        case 1: {
            printf(ANSI_COLOR_YELLOW "\n\n\t\t\tGeneración y Recuperación de Claves\n" ANSI_RESET_ALL);
            printf(ANSI_COLOR_YELLOW "\t\t\t-----------------------------------\n" ANSI_RESET_ALL);
            printf("\tIndica la dirección donde esta guardado tu archivo: ");
            cin >> save;
            printf("\tSe ha guardado con éxito.\n");
            if (save == "") {
                printf("\tIngresa una dirección válida.");
            }
            else {
                cout << "\tLa dirección es: " << save << "\n";
            }
            randombytes_buf(k, crypto_stream_chacha20_KEYBYTES);
            ofstream file;
            printf("\n\tNombre del documento para guardar tu llave (Ej. 'Llave.txt'): ");
            cin >> vacio;
            ubi = save + vacio;
            file.open(ubi);
            file << k;
            file.close();
            printf("\tLlave generada con éxito.");

            int sino;
            printf("\n\n\t¿Deseas ver tu llave generada? (1)SI - (2)NO: ");
            scanf("%d", &sino);
            if (sino == 1) {
                printf("\tIngresa el nombre del documento que contiene tu llave: ");
                cin >> vacio;
                ubi = save + vacio;
                string nombreArchivo = (ubi);
                ifstream contrasena_recu(nombreArchivo.c_str());
                while (!contrasena_recu.eof()) {
                    contrasena_recu >> y;
                    dockey += " " + y;
                }
                contrasena_recu.close();
                key = dockey.c_str();
                printf("\tLlave: %x\n", key);
            }
            else if (sino == 2) {
                break;
            }
            else {
                printf("\t\nInserta 1 o 2.");
            }
        }    
            break;
 
        case 2: {
            printf(ANSI_COLOR_YELLOW "\n\n\t\t\tCifrado de Archivos\n" ANSI_RESET_ALL);
            printf(ANSI_COLOR_YELLOW "\t\t\t-------------------\n" ANSI_RESET_ALL);
            printf("\n\tDocumento a cifrar (Ej. 'Texto.txt'): ");
            cin >> vacio;
            ubi = save + vacio;
            string nombreArchivo = (ubi);
            ifstream archivo(nombreArchivo.c_str());
            while (!archivo.eof()) {
                archivo >> x;
                doc += " " + x;
            }
            archivo.close();
            deci2 = doc.c_str();
            const unsigned char* deci;
            deci = (const unsigned char*)deci2;
            randombytes_buf(n, crypto_stream_chacha20_NONCEBYTES);  //NONCEBYTES regresa el numero aleatorio en bytes
            mlen = sizeof(deci);
            crypto_stream_chacha20_xor(c, deci, mlen, n, k);    //Encripta el texto utilizando tamaño mlen, un nonce y una k (llave secreta) 
            ofstream file;
            file.open(ubi);
            file << c;
            file.close();
            printf("\tSe ha cifrado con éxito.");
            break;
        }
        case 3: {
            printf(ANSI_COLOR_YELLOW "\n\n\t\t\tDescifrado de Archivos\n" ANSI_RESET_ALL);
            printf(ANSI_COLOR_YELLOW "\t\t\t---------------------\n" ANSI_RESET_ALL);
            cout << "\n\tDocumento a descifrar (Ej. 'Texto.txt'): ";
            cin >> vacio;
            ubi = save + vacio;
            string nombreArchivo = (ubi);
            ifstream archivo(nombreArchivo.c_str());
            while (!archivo.eof()) {
                archivo >> x;
                doc += " " + x;
            }
            archivo.close();
            deci2 = doc.c_str();
            unsigned char* deci;
            deci = (unsigned char*)(deci2);
            mlen = sizeof(deci);
            crypto_stream_chacha20_xor(c, deci, mlen, n, k);
            ofstream file;
            file.open(ubi);
            file << deci;
            file.close();
            printf("\tSe ha descifrado con éxito.");

            break;
        }
        case 4: {
            printf(ANSI_COLOR_YELLOW "\n\n\t\t\tFirma de Archivos\n" ANSI_RESET_ALL);
            printf(ANSI_COLOR_YELLOW "\t\t\t-----------------\n" ANSI_RESET_ALL);
            if (crypto_kx_client_session_keys(server_rx, server_tx, server_pk, server_sk, client_pk) != 0) {
                exit(1);
            }
            unsigned char* reto = (unsigned char*)(doc.c_str());
            unsigned char IDali[(sizeof(doc))] = "alicia.gomezg@iteso.mx";
            for (int i = 100; i < sizeof(doc); i++) {
                IDali[i] = reto[i];
            }
            unsigned char MAC[crypto_auth_hmacsha512_BYTES];
            crypto_auth_hmacsha512(MAC, IDali, (sizeof(doc)), client_tx);
            cout << "\n\tFirma: " << MAC << "";
            break;
        }
        case 5: {
            printf(ANSI_COLOR_YELLOW "\n\n\t\t\tVerificación de Firma de Archivos\n" ANSI_RESET_ALL);
            printf(ANSI_COLOR_YELLOW "\t\t\t---------------------------------\n" ANSI_RESET_ALL);
            if (crypto_kx_client_session_keys(server_rx, server_tx, server_pk, server_sk, client_pk) != 0) {
                exit(1);
            }
            unsigned char* reto = (unsigned char*)(doc.c_str());
            unsigned char IDali[(sizeof(doc))] = "alicia.gomezg@iteso.mx";
            for (int i = 100; i < sizeof(doc); i++) {
                IDali[i] = reto[i];
            }
            unsigned char MAC[crypto_auth_hmacsha512_BYTES];
            crypto_auth_hmacsha512(MAC, IDali, (sizeof(doc)), client_tx);
            if (MAC == MAC) {
                printf("\tVerificando...");
                Sleep(5000);
                printf("\n\tEl archivo y la firma coinciden.\n");
            }
            else {
                printf("\tEl archivo y la firma no coinciden.\n");
            }
            break;
        }
        case 6: {
            printf("\n\t¡Gracias por usar mi programa!\n");
            exit(0);
            break;
        }
        default:printf("\n\t¡Ingresa un número del 1 al 6!");
        }
    } while (menup != 6);
    return 0;
}
