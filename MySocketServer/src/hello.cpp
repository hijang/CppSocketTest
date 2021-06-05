#include <iostream>
#include <vector>
#include "NetworkTCP.h"

static std::vector<unsigned char> sendbuff;

int main(int argc, char *argv[])
{
    std::cout << "Hello code" << std::endl;

    while (1) {
        TTcpListenPort      *TcpListenPort;
        TTcpConnectedPort   *TcpConnectedPort;
        struct sockaddr_in cli_addr;
        socklen_t          clilen;

        //  Listen
        if ((TcpListenPort = OpenTcpListenPort(5555)) == NULL)
        {
            printf("OpenTcpListenPortFiled\n");
            return(-1);
        }
        
        clilen = sizeof(cli_addr);
        printf("Listening for connections\n");
        if  ((TcpConnectedPort=AcceptTcpConnection(TcpListenPort,&cli_addr,&clilen))==NULL)
        {  
        printf("AcceptTcpConnection Failed\n");
        return(-1); 
        }

        std::string msg_to_send = "Hi There~!!!";

        printf("Accepted connection Request\n");
        {
            unsigned int data_size = msg_to_send.length() + 1;
            if (WriteDataTcp(TcpConnectedPort, (unsigned char *)&data_size, sizeof(data_size)) != sizeof(data_size))
            {
                printf("Mismatch write data\n");
                return(-1);
            }
            WriteDataTcp(TcpConnectedPort, (unsigned char*)msg_to_send.c_str(), data_size);
        }

        printf("Data sent and closing\n");
        CloseTcpConnectedPort(&TcpConnectedPort);
    }  

    return 0;
}