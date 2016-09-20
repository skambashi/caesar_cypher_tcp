#include <stdio.h>
#include <stdlib.h> // atoi
#include <string.h> // strlen
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> // inet_addr

#define MESSAGE_SIZE 10000000
#define HEADER_SIZE 8
#define BACKLOG 10
typedef uint8_t U8; // unsigned char
typedef uint16_t U16; // unsigned short
typedef uint32_t U32; // unsigned int

const char letters[26] = { 'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z' };

// Taken from Locklessinc's (http://locklessinc.com/articles/tcp_checksum/) example checksum algorithm checksum1
U16 calculateChecksum(const char *buf, U32 size) {
    uint64_t sum = 0;
    int i;

    // Accumulate checksum
    for(i = 0; i < size - 1; i += 2) {
        U16 word16 = *(U16 *) &buf[i];
        sum += word16;
    }

    // Handle odd-sized case
    if(size & 1) {
        U16 word16 = (U8) buf[i];
        sum += word16;
    }

    // Fold to get the ones-complement result
    while(sum >> 16) sum = (sum & 0xFFFF)+(sum >> 16);

    // Invert to get the negative in ones-complement arithmetic
    return (U16)~sum;
}

int receiveMessage(int sockfd, char* buffer) {
    int totalBytesReceived = 0;

    // Receive first packet and get the message size from header
    int receivedBytes = recv(sockfd, buffer, MESSAGE_SIZE, 0);
    if(receivedBytes <= 0) {
        // fprintf(stderr, "[ERROR] First Receive Failed, errno: %d | %s.\n", errno, strerror(errno));
        return -1;
    }
    totalBytesReceived += receivedBytes;
    U32 lengthNetwork = 0;
    memcpy(&lengthNetwork, buffer+4, sizeof(U32));
    U32 messageLengthServer = ntohl(lengthNetwork);

    // Continue to receive packets until all the packets for the message have been stored in buffer
    while(totalBytesReceived < messageLengthServer) {
        receivedBytes = recv(sockfd, buffer+totalBytesReceived, MESSAGE_SIZE, 0);
        totalBytesReceived += receivedBytes;
        if(receivedBytes <= 0) {
            fprintf(stderr, "[ERROR] Receive Failed, errno: %d | %s.\n", errno, strerror(errno));
            return -1;
        }
    }

    // Calculate checksum of the whole message, and check header values for valid input
    U16 checksumServer = 0;
    memcpy(&checksumServer, buffer+2, sizeof(U16));
    memset(buffer+2, 0, sizeof(U16));
    U16 checksum = calculateChecksum(buffer, messageLengthServer);
    if (checksumServer != checksum) { fprintf(stderr, "[ERROR] Checksums are different.\n"); return -1; }
    if (buffer[0] != 0 && buffer[0] != 1) { fprintf(stderr, "[ERROR] Invalid operation in header.\n"); return -1; }
    if (buffer[1] < 0) { fprintf(stderr, "[ERROR] Invalid shift in header.\n"); return -1; }
    if (messageLengthServer != totalBytesReceived) { fprintf(stderr, "[ERROR] Invalid amount of data received.\n"); return -1; }

    // Output the message to stdout once verification passes
    // for(int i = 8; i < totalBytesReceived; i++) {
    //     fprintf(stdout, "%c", buffer[i]);
    // }

    return totalBytesReceived;
}

int sendMessage(int sockfd, char* buffer, U32 length, U8 operation, U8 shift) {
    // Write header info for message
    buffer[0] = operation;
    buffer[1] = shift;
    U32 lengthNetwork = htonl(length);
    memcpy(buffer+4, (char*)&lengthNetwork, sizeof(U32));

    // Calculate checksum and store in byte array as well
    memset(buffer+2, 0, sizeof(U16));
    U16 checksum = calculateChecksum(buffer, length);
    memcpy(buffer+2, (char*)&checksum, sizeof(U16));

    // Continue to send parts of the message until whole message has been sent
    int sentBytes;
    U32 totalBytesSent = 0;
    while(totalBytesSent < length) {
        sentBytes = send(sockfd, buffer, (length - totalBytesSent), 0);
        if(sentBytes <= 0) {
            fprintf(stderr, "[ERROR] Send Failed, errno: %d | %s.\n", errno, strerror(errno));
            return -1;
        }
        buffer += sentBytes;
        totalBytesSent += sentBytes;
    }

    return totalBytesSent;
}

char uncapitalize(int c) {
    switch(c) {
        case 'a': case 'A':
            return 'a';
        case 'b': case 'B':
            return 'b';
        case 'c': case 'C':
            return 'c';
        case 'd': case 'D':
            return 'd';
        case 'e': case 'E':
            return 'e';
        case 'f': case 'F':
            return 'f';
        case 'g': case 'G':
            return 'g';
        case 'h': case 'H':
            return 'h';
        case 'i': case 'I':
            return 'i';
        case 'j': case 'J':
            return 'j';
        case 'k': case 'K':
            return 'k';
        case 'l': case 'L':
            return 'l';
        case 'm': case 'M':
            return 'm';
        case 'n': case 'N':
            return 'n';
        case 'o': case 'O':
            return 'o';
        case 'p': case 'P':
            return 'p';
        case 'q': case 'Q':
            return 'q';
        case 'r': case 'R':
            return 'r';
        case 's': case 'S':
            return 's';
        case 't': case 'T':
            return 't';
        case 'u': case 'U':
            return 'u';
        case 'v': case 'V':
            return 'v';
        case 'w': case 'W':
            return 'w';
        case 'x': case 'X':
            return 'x';
        case 'y': case 'Y':
            return 'y';
        case 'z': case 'Z':
            return 'z';
        default:
            return EOF;
    }
}

void shifter(char* buffer, U32 length, U8 s) {
    for (int i = HEADER_SIZE; i < length; i++) {
        int c = uncapitalize(buffer[i]);
        if (c != EOF) {
            c = c-97; // a = 0
            c = (c + s)%26;
            buffer[i] = letters[c];
        }
    }
}

int main(int argc , char *argv[]) {
    U16 port; // -p, port of server

    // Get the arguments
    for(int i = 1; i < argc; i++) {  // Skip argv[0]
        if(strcmp(argv[i], "-p") == 0) { port = atoi(argv[++i]); }
    }

    fprintf(stderr, "[INFO] PORT: %d\n", port);

    // Setup listening socket for new client connection requests
    int listenfd;
    struct sockaddr_in server;

    // Create socket
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if(listenfd < 0) { fprintf(stderr, "[ERROR] Could not create socket.\n"); return 1; }
    else { fprintf(stderr, "[INFO] Socket %d created\n", listenfd); }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(port);
    memset(server.sin_zero, '\0', sizeof server.sin_zero);

    // Bind to host address
    if (bind(listenfd, (struct sockaddr *) &server, sizeof(server)) < 0) {
        close(listenfd);
        fprintf(stderr, "[ERROR] Bind Failed, errno: %d | %s.\n", errno, strerror(errno));
        return 1;
    } else { fprintf(stderr, "[INFO] Server successfully bound\n"); }

    // Listen for client connection reqs on listenfd
    if (listen(listenfd, BACKLOG) < 0) {
        fprintf(stderr, "[ERROR] Listen Failed, errno: %d | %s.\n", errno, strerror(errno));
        return 1;
    } else { fprintf(stderr, "[INFO] Server listening for connection request\n"); }

    while(1) {
        char* buffer = malloc(MESSAGE_SIZE);
        int connfd = accept(listenfd, (struct sockaddr *)NULL, NULL);
        if (connfd < 0) { fprintf(stderr, "[WARNING] Accept of client connection request failed.\n"); continue; }

        if (!fork()) { // this is the child process
            close(listenfd); // child doesn't need the listener

            while(1) {
                int bytesSent, bytesReceived;
                if ((bytesReceived = receiveMessage(connfd, buffer)) < 0) {
                    // fprintf(stderr, "[ERROR] Fatal error while receiving message.\n");
                    fprintf(stderr, "[INFO] Client connection closed.\n");
                    close(connfd); exit(0);
                } else {
                    fprintf(stderr, "[INFO] Received message from client of size %d.\n", bytesReceived);
                    U8 operation = buffer[0];
                    U8 shift = buffer[1];
                    if (operation == 0) { shifter(buffer, bytesReceived, shift%26); } // encrypt
                    else { shifter(buffer, bytesReceived, 26-shift%26); } // decrypt
                    if ((bytesSent = sendMessage(connfd, buffer, bytesReceived, operation, shift)) < 0) {
                        fprintf(stderr, "[ERROR] Fatal error while sending message.\n");
                        close(connfd); exit(0);
                    }
                }
                if (bytesSent != bytesReceived) {
                    fprintf(stderr, "[ERROR] Bytes sent was not equal to bytes received.\n");
                    close(connfd); exit(0);
                }
            }
        }
        close(connfd);  // parent doesn't need this
        free(buffer);
    }
    close(listenfd);

    // U8 shift = 26;
    // char test[] = "abcdefghijklmnopqrstuvwxyz";
    // fprintf(stderr, "shift: %d\n%s\n", shift, test);
    // shifter(test, 26, 26-shift%26);
    // fprintf(stderr, "%s\n", test);
    return 0;
}
