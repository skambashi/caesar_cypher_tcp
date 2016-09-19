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
typedef uint8_t U8; // unsigned char
typedef uint16_t U16; // unsigned short
typedef uint32_t U32; // unsigned int

/* Taken from Locklessinc's (http://locklessinc.com/articles/tcp_checksum/) example checksum algorithm checksum1 */
U16 calculateChecksum(const char *buf, U32 size) {
    uint64_t sum = 0;
    int i;

    /* Accumulate checksum */
    for(i = 0; i < size - 1; i += 2) {
        U16 word16 = *(U16 *) &buf[i];
        sum += word16;
    }

    /* Handle odd-sized case */
    if(size & 1) {
        U16 word16 = (U8) buf[i];
        sum += word16;
    }

    while(sum >> 16) sum = (sum & 0xFFFF)+(sum >> 16); /* Fold to get the ones-complement result */
    return (U16)~sum; /* Invert to get the negative in ones-complement arithmetic */
}

int receiveMessage(int sockfd, char* buffer, int length) {
    int sumTotalReceivedBytes = 0;
    while(sumTotalReceivedBytes < length) {
        int totalBytesReceived = 0;
        int receivedBytes = recv(sockfd, buffer, MESSAGE_SIZE, 0);
        if(receivedBytes <= 0) {
            fprintf(stderr, "[ERROR] First Receive Failed \n");
            fprintf(stderr, "[ERROR] Value of errno: %d\n", errno);
            fprintf(stderr, "[ERROR] Error opening file: %s\n", strerror(errno));
            return -1;
        }
        totalBytesReceived += receivedBytes;
        U32 lengthNetwork = 0;
        memcpy(&lengthNetwork, buffer+4, sizeof(U32));
        U32 messageLengthServer = ntohl(lengthNetwork);

        // fprintf(stderr, "[HEADER] Operation: %d\n", buffer[0]);
        // fprintf(stderr, "[HEADER] Shift: %d\n", buffer[1]);
        // fprintf(stderr, "[HEADER] Known Length: %d\n", length);
        // fprintf(stderr, "[HEADER] Length of server message: %d\n", messageLengthServer);

        while(totalBytesReceived < messageLengthServer) {
            receivedBytes = recv(sockfd, buffer+totalBytesReceived, MESSAGE_SIZE, 0);
            totalBytesReceived += receivedBytes;
            if(receivedBytes <= 0) {
                fprintf(stderr, "[ERROR] Receive Failed \n");
                fprintf(stderr, "[ERROR] Value of errno: %d\n", errno);
                fprintf(stderr, "[ERROR] Error opening file: %s\n", strerror(errno));
                return -1;
            }
        }

        U16 checksumServer = 0;
        memcpy(&checksumServer, buffer+2, sizeof(U16));
        memset(buffer+2, 0, sizeof(U16));
        U16 checksum = calculateChecksum(buffer, messageLengthServer);
        if (checksumServer != checksum) { fprintf(stderr, "[ERROR] CHECKSUMS DIFFERENT. \n"); return -1; }
        if (buffer[0] != 0 && buffer[0] != 1) { fprintf(stderr, "[ERROR] INVALID OPERATION. \n"); return -1; }
        if (buffer[1] < 0) { fprintf(stderr, "[ERROR] INVALID SHIFT. \n"); return -1; }

        for(int i = 8; i < totalBytesReceived; i++) {
            fprintf(stdout, "%c", buffer[i]);
        }
        sumTotalReceivedBytes += totalBytesReceived;
    }

    return sumTotalReceivedBytes;
}

int sendMessage(int sockfd, char* buffer, U32 length, U8 operation, U8 shift) {
    buffer[0] = operation;
    buffer[1] = shift;
    memset(buffer+2, 0, sizeof(U16));
    U32 lengthNetwork = htonl(length);
    memcpy(buffer+4, (char*)&lengthNetwork, sizeof(U32));
    U16 checksum = calculateChecksum(buffer, length);
    memcpy(buffer+2, (char*)&checksum, sizeof(U16));

    lengthNetwork = 0;
    memcpy(&lengthNetwork, buffer+4, sizeof(U32));

    // fprintf(stderr, "[HEADER] Operation: %d\n", buffer[0]);
    // fprintf(stderr, "[HEADER] Shift: %d\n", buffer[1]);
    // fprintf(stderr, "[HEADER] Known Length: %d\n", length);
    // fprintf(stderr, "[HEADER] Length From Byte Array: %d\n", messageLengthServer);
    // fprintf(stderr, "[HEADER] Length in byte array: %d\n", ((buffer[4]<<24 & 0xFF000000) | (buffer[5]<<16 & 0xFF0000) | (buffer[6]<<8 & 0xFF00) | (buffer[7] & 0xFF)));

    int sentBytes;
    U32 totalBytesSent = 0;
    while(totalBytesSent < length) {
        sentBytes = send(sockfd, buffer, (length - totalBytesSent), 0);
        if(sentBytes <= 0) {
            fprintf(stderr, "[ERROR] Send Failed \n");
            fprintf(stderr, "[ERROR] Value of errno: %d\n", errno);
            fprintf(stderr, "[ERROR] Error opening file: %s\n", strerror(errno));
            return -1;
        }
        buffer += sentBytes;
        totalBytesSent += sentBytes;
    }

    return totalBytesSent;
}

int exchange(int sockfd, char* buffer, U32 length, U8 operation, U8 shift) {
    // fprintf(stderr, "\n[INFO] EXCHANGE MESSAGE \n");
    int bytesSent, bytesReceived;
    if ((bytesSent = sendMessage(sockfd, buffer, length, operation, shift)) < 0) { fprintf(stderr, "ERROR WHILE SENDING MESSAGE.\n"); return -1; }
    if ((bytesReceived = receiveMessage(sockfd, buffer, length)) < 0) { fprintf(stderr, "ERROR WHILE RECEIVING MESSAGE.\n"); return -1; }
    if (bytesSent != bytesReceived) { fprintf(stderr, "ERROR WHILE EXCHANGE.\n"); return -1; }
    return bytesSent;
}

int main(int argc , char *argv[]) {
    U8 operation; // -o, 8 bits, 0 - encrypt | 1 - decrypt
    U8 shift; // -s, 8 bits, caesar cypher shift amount
    U16 port; // -p, port of server
    char* ip; // -h, hostname/ip address of server

    // GETTING ARGUMENTS
    //==================
    for(int i = 1; i < argc; i++) {  // Skip argv[0]
        if(strcmp(argv[i], "-o") == 0) { operation = atoi(argv[++i]); }
        else if(strcmp(argv[i], "-s") == 0) { shift = atoi(argv[++i]); }
        else if(strcmp(argv[i], "-p") == 0) { port = atoi(argv[++i]); }
        // else if(strcmp(argv[i], "-p") == 0) { port = argv[++i]; }
        else if(strcmp(argv[i], "-h") == 0) { ip = argv[++i]; }
    }
    fprintf(stderr, "[INFO] OPERATION: %d\n", operation);
    fprintf(stderr, "[INFO] SHIFT: %d\n", shift);
    fprintf(stderr, "[INFO] PORT: %d\n", port);
    fprintf(stderr, "[INFO] IP: %s\n", ip);

    // CONNECT TO SERVER
    //==================
    int sockfd;
    struct sockaddr_in server;

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {
        fprintf(stderr, "[ERROR] Could not create socket \n");
        return 1;
    } else {
        fprintf(stderr, "[INFO] SOCKET %d CREATED \n", sockfd);
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);     // short, network byte order
    server.sin_addr.s_addr = inet_addr(ip);
    memset(server.sin_zero, '\0', sizeof server.sin_zero);

    // Connect to remote server
    if(connect(sockfd, (struct sockaddr *)&server, sizeof(server)) < 0) {
        fprintf(stderr, "[ERROR] Connect Failed \n");
        return 1;
    } else {
        fprintf(stderr, "[INFO] CONNECTED TO SOCKET \n");
    }

    // GET INPUT
    //==========
    char* buffer = malloc(MESSAGE_SIZE);
    U32 length = HEADER_SIZE;
    U32 finalInputLength = 0;
    U32 finalExchanged = 0;

    int c;
    while ((c = getchar()) != EOF) {
        if ((char)c == '\0') { fprintf(stderr, "[WARNING] Input contains null character."); continue; }
        buffer[length++] = (char)c;
        if(length == MESSAGE_SIZE) {
            finalInputLength += length;
            int result = exchange(sockfd, buffer, length, operation, shift);
            if (result < 0) { fprintf(stderr, "ERROR WHILE EXCHANGING MESSAGE.\n"); return 1; }
            finalExchanged += result;
            // fprintf(stderr, "\n[INFO] TOTAL INPUT: %d | TOTAL EXCHANGED: %d | EXCHANGED %d\n", finalInputLength, finalExchanged, result);
            length = HEADER_SIZE;
        }
    }
    if(length > HEADER_SIZE) {
        finalInputLength += length;
        int result = exchange(sockfd, buffer, length, operation, shift);
        if (result < 0) { fprintf(stderr, "ERROR WHILE EXCHANGING MESSAGE.\n"); return 1; }
        finalExchanged += result;
        // fprintf(stderr, "\n[INFO] TOTAL INPUT: %d | TOTAL EXCHANGED: %d | EXCHANGED %d\n", finalInputLength, finalExchanged, result);
        length = HEADER_SIZE;
    }

    fprintf(stderr, "\n[INFO] TOTAL SIZE OF MESSAGE WAS %d BYTES. \n", finalInputLength);
    if(finalInputLength <= 0) { return 0; }

    close(sockfd);
    free(buffer);
    return 0;
}
