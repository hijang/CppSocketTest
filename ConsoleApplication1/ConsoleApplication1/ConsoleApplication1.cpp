// ConsoleApplication1.cpp : 이 파일에는 'main' 함수가 포함됩니다. 거기서 프로그램 실행이 시작되고 종료됩니다.
//

#include <iostream>
#include "NetworkTCP.h"

int main()
{
    std::cout << "Hello World!\n";

    TTcpConnectedPort* TcpConnectedPort = NULL;
    bool retvalue;
    const char* hostname = "172.27.59.14";
    const char* port = "5555";

    if ((TcpConnectedPort = OpenTcpConnection(hostname, port)) == NULL)  // Open UDP Network port
    {
        printf("OpenTcpConnection\n");
        return(-1);
    }

    printf("Connected~!\n");
    {
        unsigned int imagesize;
        unsigned char* buff;	/* receive buffer */

        if (ReadDataTcp(TcpConnectedPort, (unsigned char*)&imagesize, sizeof(imagesize)) != sizeof(imagesize)) return(false);

        //imagesize = ntohl(imagesize); // convert image size to host format

        printf("imagesize??? %d\n", imagesize);
        if (imagesize < 0) return false;

        buff = new (std::nothrow) unsigned char[imagesize];
        if (buff == NULL) return false;
        memset(buff, imagesize, 0x00);

        ReadDataTcp(TcpConnectedPort, buff, imagesize);

        printf("%s\n", buff);
        return false;
    }

    CloseTcpConnectedPort(&TcpConnectedPort); // Close network port;
    return 0;
}

// 프로그램 실행: <Ctrl+F5> 또는 [디버그] > [디버깅하지 않고 시작] 메뉴
// 프로그램 디버그: <F5> 키 또는 [디버그] > [디버깅 시작] 메뉴

// 시작을 위한 팁: 
//   1. [솔루션 탐색기] 창을 사용하여 파일을 추가/관리합니다.
//   2. [팀 탐색기] 창을 사용하여 소스 제어에 연결합니다.
//   3. [출력] 창을 사용하여 빌드 출력 및 기타 메시지를 확인합니다.
//   4. [오류 목록] 창을 사용하여 오류를 봅니다.
//   5. [프로젝트] > [새 항목 추가]로 이동하여 새 코드 파일을 만들거나, [프로젝트] > [기존 항목 추가]로 이동하여 기존 코드 파일을 프로젝트에 추가합니다.
//   6. 나중에 이 프로젝트를 다시 열려면 [파일] > [열기] > [프로젝트]로 이동하고 .sln 파일을 선택합니다.
