#pragma comment(lib, "libcurl_imp.lib")
#pragma comment(lib, "jsoncpp.lib")
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <curl/curl.h>
#include <json/json.h>
#include <iostream>
#include <winsock2.h>
#include <fstream>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <WS2tcpip.h>
#include <errno.h>
#include <sys/types.h>

#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable:4996)

#define PORT 4888 // port, na którym programy będą się komunikować
using namespace std;

void appShutdown(int errLine, SOCKET server_socket, SSL_CTX* ctx, SSL* ssl) {
    if (ssl != 0) {
        SSL_shutdown(ssl); // kończy bezpieczne połączenie SSL
        SSL_free(ssl); // zwalnia pamięć zaalokowaną dla zmiennej ssl, która przechowuje informacje o połączeniu SSL
    }
    if (server_socket != 0) closesocket(server_socket); // zamyka gniazdo serwera

    if (&ctx != 0) SSL_CTX_free(ctx); // zwalnia pamięć zaalokowaną dla kontekstu SSL
    WSACleanup(); // kończy pracę z Winsock 
    
    throw errLine;
}

int main()
{
    try {
        SOCKET server_socket = 0;
        SSL* ssl = 0;
        SSL_CTX* ctx = 0;
        const int bufferSize = 1024; // deklaracja wielkości buforu

        system("title TSL Server"); // nadanie nazwy konsoli

        sockaddr_in server; // inicjalizacja struktury serwera

        WSADATA wsa; // inicjalizacja Winsocka
        printf("Inicjalizacja Winsocka...");
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        {
            printf("Nie udalo sie utworzyc polaczenia winsock: %d", WSAGetLastError());
            appShutdown(__LINE__, server_socket, ctx, ssl);
        }
        printf("Zainicjalizowano.\n");

        
        if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) // w przypadku TCP druga zmienna to SOCK_STREAM
        {
            printf("Nie udalo sie utworzyc socketu: %d", WSAGetLastError());
            appShutdown(__LINE__, server_socket, ctx, ssl);
        }
        printf("Socket utworzony.\n");

        // przygotowanie struktury sockaddr_in
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = INADDR_ANY;
        server.sin_port = htons(PORT);

        // bindowanie
        if (bind(server_socket, (sockaddr*)&server, sizeof(server)) == SOCKET_ERROR)
        {
            printf("Bindowanie zwrocilo blad: %d", WSAGetLastError());
            appShutdown(__LINE__, server_socket, ctx, ssl);
        }
        puts("Bindowanie udalo sie.");
        // nasłuchiwanie od jednego klienta
        if (listen(server_socket, 1) == SOCKET_ERROR) {
            printf("Blad nasluchu: %d", WSAGetLastError());
            appShutdown(__LINE__, server_socket, ctx, ssl);
        }
        puts("Inicjalizacja nasluchu udala sie.");

        ctx = SSL_CTX_new(TLS_server_method()); // inicjalizacja kontekstu SSL

        if (ctx == NULL) {
            cout << "W SSL_CTX_new wystapil blad" << endl;
            ERR_print_errors_fp(stderr);
            appShutdown(__LINE__, server_socket, ctx, ssl);
        }

        if (SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) != 1) {
            cout << "W SSL_CTX_load_verify_locations wystapil blad" << endl;
            ERR_print_errors_fp(stderr);
            appShutdown(__LINE__, server_socket, ctx, ssl);
        }

        if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            cout << "W SSL_CTX_set_default_verify_paths wystapil blad" << endl;
            ERR_print_errors_fp(stderr);
            appShutdown(__LINE__, server_socket, ctx, ssl);
        }

        // Wczytanie certyfikatu serwera
        if (SSL_CTX_use_certificate_file(ctx, "ServerDPKK.crt", SSL_FILETYPE_PEM) != 1) {
            cout << "W SSL_CTX_use_certificate_file wystapil blad" << endl;
            ERR_print_errors_fp(stderr);
            appShutdown(__LINE__, server_socket, ctx, ssl);
        }

        // Wczytanie klucza prywatnego serwera
        if (SSL_CTX_use_PrivateKey_file(ctx, "ServerDPKK.key", SSL_FILETYPE_PEM) != 1) {
            cout << "W SSL_CTX_use_PrivateKey_file wystapil blad" << endl;
            ERR_print_errors_fp(stderr);
            appShutdown(__LINE__, server_socket, ctx, ssl);
        }

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

        fstream file;
        char buffer[bufferSize];
        string output;
        int message_len;
        int clientFd;
        // Tworzenie struktury SSL dla połączenia z klientem

        while (true) {
            char ipstr[INET_ADDRSTRLEN];

            int slen = sizeof(server);

            // akceptacja połączenia od klienta
            if ((clientFd = accept(server_socket, (struct sockaddr*)&server, &slen)) == SOCKET_ERROR) {
                printf("Blad akceptacji: %d", WSAGetLastError());
                continue;
            }

            // pobranie adresu klienta
            if (inet_ntop(AF_INET, &server.sin_addr, ipstr, INET_ADDRSTRLEN) == NULL) {
                cout << "Nie udalo sie pobrac adresu klienta" << endl;
                closesocket(clientFd);
                continue;
            }

            ssl = SSL_new(ctx); // tworzenie nowego obiektu SSL
            if (ssl == NULL) {
                closesocket(clientFd);
                continue;
            }
            if (SSL_set_fd(ssl, clientFd) != 1) { // Ustawianie deskryptora pliku dla połączenia SSL
                SSL_free(ssl); // zwalnia pamięć zaalokowaną dla zmiennej ssl, która przechowuje informacje o połączeniu SSL
                closesocket(clientFd);
                continue;
            }

            // Akceptowanie połączenia SSL
            if (SSL_accept(ssl) != 1) {
                ERR_print_errors_fp(stderr);
                SSL_free(ssl); // zwalnia pamięć zaalokowaną dla zmiennej ssl, która przechowuje informacje o połączeniu SSL
                closesocket(clientFd);
                continue;
            }

            // przypisanie do zmiennej s adresu klienta
            string s(ipstr);

            cout << "Zaakceptowano polaczenie uzytkownika: " << s << endl;
       
            // pętla służąca do odczytu pakietów i zapisu do pliku
            while ((message_len = SSL_read(ssl, buffer, sizeof(buffer))) > 0)
            {
                output.append(buffer, message_len);
            }

            // poszukiwanie poszczególnych fragmentów ciągu znaków
            Json::Reader reader;
            Json::Value js;
            string temperatura, cisnienie;
            cout << "Odczytano dane od uzytkownika: " << s << endl;
            if (reader.parse(output, js)) //parsowanie json 
            { //zabezpieczenie na wypadek gdyby zwrócono wartość inną niż liczba 
                try { temperatura = js.get("temperatura", "NaN").asString(); }
                catch (std::invalid_argument) { temperatura = ""; }
                try { cisnienie = js.get("cisnienie", "NaN").asString(); }
                catch (std::invalid_argument) { cisnienie = ""; }
            }
            cout << "Stacja:" << js.get("stacja", "NULL").asString() << "\nTemperatura: " << temperatura << " *C;\n" << "Cisnienie: " << cisnienie << " hPa" << endl;

            output = "";

            SSL_shutdown(ssl); // kończy bezpieczne połączenie SSL
            SSL_free(ssl); // zwalnia pamięć zaalokowaną dla zmiennej ssl, która przechowuje informacje o połączeniu SSL
            closesocket(clientFd); // zamyka gniazdo klienta    
        }

        closesocket(server_socket); // zamyka gniazdo serwera
        SSL_CTX_free(ctx); // zwalnia pamięć zaalokowaną dla kontekstu SSL
        WSACleanup(); // kończy pracę z Winsock
        return 0;
    }

    catch (int ex) {
        cout << "Program zakończył działanie z kodem: " << ex << endl;
    }
}

