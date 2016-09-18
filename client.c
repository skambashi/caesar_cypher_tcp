#include <stdio.h>
#include <stdlib.h> // atoi
#include <string.h> // strlen
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> // inet_addr

#define MESSAGE_SIZE 1000
#define HEADER_SIZE 8
typedef uint8_t U8; // unsigned char
typedef int16_t U16; // unsigned short
typedef uint32_t U32; // unsigned int

/* Taken from Locklessinc's (http://locklessinc.com/articles/tcp_checksum/) example checksum algorithm checksum1 */
U16 calculateChecksum(const char *buf, unsigned size) {
    unsigned sum = 0;
    int i;

    /* Accumulate checksum */
    for (i = 0; i < size - 1; i += 2) {
        U16 word16 = *(U16 *) &buf[i];
        sum += word16;
    }

    /* Handle odd-sized case */
    if (size & 1) {
        U16 word16 = (U8) buf[i];
        sum += word16;
    }

    while (sum >> 16) sum = (sum & 0xFFFF)+(sum >> 16); /* Fold to get the ones-complement result */
    return ~sum; /* Invert to get the negative in ones-complement arithmetic */
}

int sendMessage(int sockfd, char* buffer, U32 length) {
    // fprintf(stderr, "\n[INFO] SEND MESSAGE \n");
    // fprintf(stderr, "[INFO] Setting up header info length & checksum \n");
    int lengthNetwork = htonl(length);
    memcpy(buffer+4, (char*)&lengthNetwork, sizeof(U32));
    U16 checksum = calculateChecksum(buffer, length);
    memcpy(buffer+2, (char*)&checksum, sizeof(U16));

    int sentBytes, totalBytesSent = 0;
    int currLength = length;
    while(currLength > 0) {
        // fprintf(stderr, "[INFO] Sending message! \n");
        sentBytes = send(sockfd, buffer, currLength, 0);
        totalBytesSent += sentBytes;
        if (sentBytes == 0) { fprintf(stderr, "[ERROR] Socket Closed \n"); return 1; } // socket probably closed
        else if (sentBytes < 0) {
            fprintf(stderr, "[ERROR] Send Failed \n");
            fprintf(stderr, "[ERROR] Value of errno: %d\n", errno);
            fprintf(stderr, "[ERROR] Error opening file: %s\n", strerror(errno));
            return 1;
        }
        buffer += sentBytes;
        currLength -= sentBytes;
        if (length - currLength != totalBytesSent) { fprintf(stderr, "[ERROR] MISMATCHING SEND AMOUNTS %d, %d\n", (length-currLength), totalBytesSent); return 1; }
        // fprintf(stderr, "[INFO] LENGTH: %d | TOTAL: %d | SENT %d\n", length, (length - currLength), sentBytes);
    }
    return 0;
}

int main(int argc , char *argv[]) {
    U8 operation; // -o, 8 bits, 0 - encrypt | 1 - decrypt
    U8 shift; // -s, 8 bits, caesar cypher shift amount
    U16 port; // -p, port of server
    char* ip; // -h, hostname/ip address of server

    //==========================================================================
    // GETTING ARGUMENTS
    //==========================================================================
    for (int i = 1; i < argc; i++) {  // Skip argv[0]
        if (strcmp(argv[i], "-o") == 0) { operation = atoi(argv[++i]); }
        else if (strcmp(argv[i], "-s") == 0) { shift = atoi(argv[++i]); }
        else if (strcmp(argv[i], "-p") == 0) { port = atoi(argv[++i]); }
        // else if (strcmp(argv[i], "-p") == 0) { port = argv[++i]; }
        else if (strcmp(argv[i], "-h") == 0) { ip = argv[++i]; }
    }
    fprintf(stderr, "[INFO] OPERATION: %d\n", operation);
    fprintf(stderr, "[INFO] SHIFT: %d\n", shift);
    fprintf(stderr, "[INFO] PORT: %d\n", port);
    fprintf(stderr, "[INFO] IP: %s\n", ip);

    //==========================================================================
    // CONNECT TO SERVER
    //==========================================================================
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

    //==========================================================================
    // GET INPUT
    //==========================================================================
    char* buffer = malloc(MESSAGE_SIZE);
    buffer[0] = operation;
    buffer[1] = shift; // buffer[2-3] is checksum, buffer[4-7] is length
    memset(buffer+2, 0, HEADER_SIZE-2); // memset(buffer+2, 0, sizeof(U16));
    U32 length = HEADER_SIZE;
    U32 finalInputLength = 0;

    int c;
    while ((c = getchar()) != EOF) {
        buffer[length++] = (char)c;
        if (length == MESSAGE_SIZE) {
            // SEND MESSAGE
            finalInputLength += length;
            fprintf(stderr, "[INFO] TOTAL: %d | SENT %d\n", finalInputLength, length);
            int result = sendMessage(sockfd, buffer, length);
            if (result != 0) { return result; } // if error, propagate
            memset(buffer+2, 0, HEADER_SIZE-2); // memset(buffer+2, 0, sizeof(U16));
            length = HEADER_SIZE;
        }
    }
    if (length > HEADER_SIZE) {
        finalInputLength += length;
        fprintf(stderr, "[INFO] TOTAL: %d | SENT %d\n", finalInputLength, length);
        int result = sendMessage(sockfd, buffer, length);
        if (result != 0) { return result; } // if error, propagate
    }

    fprintf(stderr, "[INFO] TOTAL SIZE OF MESSAGE WAS %d BYTES. \n", finalInputLength);
    if (finalInputLength <= 0) {
        return 0;
    }
    // fprintf(stderr, "message[%d] = %d\n", i, buffer[i]); }

    //==========================================================================
    // RECEIVE MESSAGE
    //==========================================================================
    char recvBuff[29000];
    memset(recvBuff, '0', sizeof(recvBuff));

    int receivedBytes = recv(sockfd, recvBuff, 29000, 0);
    fprintf(stderr, "[INFO] RECEIVED: %d BYTES\n", receivedBytes);
    fprintf(stderr, "[INFO] RETURNED:\n");
    for (int i = 8; i < receivedBytes; i++) {
        fprintf(stdout, "%c", recvBuff[i]);
        fprintf(stderr, "%c", recvBuff[i]);
    }
    fprintf(stderr, "\n");

    if(receivedBytes < 0) {
        fprintf(stderr, "[ERROR] Value of errno: %d\n", errno);
        fprintf(stderr, "[ERROR] Error opening file: %s\n", strerror(errno));
    }

    close(sockfd);
    free(buffer);
    return 0;
}
