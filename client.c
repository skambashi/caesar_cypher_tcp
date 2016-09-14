#include <stdio.h>
#include <stdlib.h> // atoi
#include <string.h> // strlen
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> // inet_addr

#define MESSAGE_SIZE 10000000
typedef uint8_t U8; // unsigned char
typedef int16_t U16; // unsigned short
typedef uint32_t U32; // unsigned int

unsigned short calculateChecksum(const char *buf, unsigned size) {
    unsigned sum = 0;
    	int i;

    	/* Accumulate checksum */
    	for (i = 0; i < size - 1; i += 2) {
    		unsigned short word16 = *(unsigned short *) &buf[i];
    		sum += word16;
    	}

    	/* Handle odd-sized case */
    	if (size & 1) {
    		unsigned short word16 = (unsigned char) buf[i];
    		sum += word16;
    	}

    	/* Fold to get the ones-complement result */
    	while (sum >> 16) sum = (sum & 0xFFFF)+(sum >> 16);

    	/* Invert to get the negative in ones-complement arithmetic */
    	return ~sum;
}

int main(int argc , char *argv[]) {
    U8 operation; // -o, 8 bits, 0 - encrypt | 1 - decrypt
    U8 shift; // -s, 8 bits, caesar cypher shift amount
    U32 length = 8;
    U32 lengthN;
    U16 port; // -p, port of server
    char* ip; // -h, hostname/ip address of server
    char* buffer;

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
    printf("OPERATION: %d\nSHIFT: %d\nPORT: %d\nIP: %s\n", operation, shift, port, ip);

    //==========================================================================
    // CREATING MESSAGE
    //==========================================================================
    buffer = malloc(MESSAGE_SIZE);
    memset(buffer+2, 0, sizeof(U16));
    buffer[0] = operation;
    buffer[1] = shift; // buffer[2-3] is checksum, buffer[4-7] is length
    buffer[8] = 'a'; length++;
    buffer[9] = 'a'; length++;

    lengthN = htonl(length);
    memcpy(buffer+4, (char*)&lengthN, sizeof(U32));
    U16 checksum = calculateChecksum(buffer, length);
    memcpy(buffer+2, (char*)&checksum, sizeof(U16));
    for (int i = 0; i < length; i++) {
        printf("message[%d] = %d\n", i, buffer[i]);
    }

    //==========================================================================
    // SEND MESSAGE
    //==========================================================================
    int sockfd, n = 0;
    struct sockaddr_in server;
    char recvBuff[2000];
    memset(recvBuff, '0', sizeof(recvBuff));

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {
        printf("\n Error : Could not create socket \n");
        return 1;
    } else {
        printf("\n SOCKET %d CREATED \n", sockfd);
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);     // short, network byte order
    server.sin_addr.s_addr = inet_addr(ip);
    printf("\n EQUIV IP: %d, PORT: %d \n", inet_addr(ip), htons(port));
    memset(server.sin_zero, '\0', sizeof server.sin_zero);

    // Connect to remote server
    if(connect(sockfd, (struct sockaddr *)&server, sizeof(server)) < 0) {
        printf("\n Error : Connect Failed \n");
        return 1;
    } else {
        printf("\n CONNECTED TO SOCKET \n");
    }

    // Send some data
    n = send(sockfd, buffer, length, 0);
    if(n < 0) {
        printf("\n Error : Send Failed \n");
        return 1;
    } else {
        printf("\n SENT %d BYTES TO SERVER, LENGTH OF MESSAGE WAS %d \n", n, length);
    }

    int receivedBytes = recv(sockfd, recvBuff, 2000, 0);
    printf("\n RECV RESPONSE: %d \n", receivedBytes);
    printf(" RETURNED: ");
    for (int i = 8; i < receivedBytes; i++) {
        printf("%c", recvBuff[i]);
    }
    printf("\n");

    if(n < 0) {
        printf("Value of errno: %d\n", errno);
        printf("Error opening file: %s\n", strerror(errno));
    }

    printf("\n %d BYTES RECEIVED FROM SERVER \n", n);

    close(sockfd);
    free(buffer);
    return 0;
}
