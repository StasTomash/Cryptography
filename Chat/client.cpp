#include <vector>
#include <cstring>
#include <fstream>
#include <cstdlib>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <csignal>
#include <sys/prctl.h>
#include <cstdio>
#include <unistd.h>
#include <thread>
#include "ClientUtils.h"

#define BUFFER_LEN 65535

void Send(const std::string& msg, int type, int socket) {
    char* buff = new char[msg.length() + 2];
    sprintf(buff, "%d", type);
    strcpy(buff+1, msg.c_str());
    buff[msg.length()+1] = '\0';
//    std::cout << "Sending " << buff << "\n";
    send(socket, buff, strlen(buff), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
}

int Receive(int socket, char* buff, int buffSize) {
    memset(buff, 0, buffSize);
    int len = recv(socket, buff, buffSize, 0);
//    std::cout << "Received: " << buff << "\n";
    return len;
}

int main(int argc, char** argv) {
    if (argc != 5) {
        fprintf(stderr, "Format should be: ./Client SERVER_IP SERVER_PORT CLIENT_PORT");
        exit(EXIT_FAILURE);
    }
    char* SERVER_IP = argv[1];
    char* dummy;
    int SERVER_PORT = (int)strtol(argv[2], &dummy, 10);
    int CLIENT_PORT = (int)strtol(argv[3], &dummy, 10);
    if (!CLIENT_PORT || !SERVER_PORT) {
        fprintf(stderr, "Illegal port");
        exit(EXIT_FAILURE);
    }
    std::fstream chat;
    chat.open(argv[4], std::fstream::out | std::fstream::trunc);
    if (chat.fail()) {
        fprintf(stderr, "Couldn't open file");
        exit(EXIT_FAILURE);
    }

    ClientInfo ci;

    struct sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);

    int sock;
    CHECK(sock = socket(AF_INET, SOCK_STREAM, 0), "Error creating socket");
    CHECK(inet_pton(AF_INET, SERVER_IP, &serverAddr.sin_addr), "Invalid server IP");
    CHECK(connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)), "Connection failed");

    char* buffer = new char[BUFFER_LEN];
    size_t respLen;
    CHECK((respLen = Receive(sock, buffer, BUFFER_LEN)), "Error reading from socket");
    if (!ClientMessageProcessor::ParseServerKeyDistribution(buffer, respLen, ci)) {
        exit(EXIT_FAILURE);
    }
    while (true) {
        printf("Input your login please: \n");
        std::string login;
        std::getline(std::cin, login);
        std::string msg;
        int msgType;
        ClientMessageProcessor::PrepareRegistration(msg, msgType, login, ci);
        Send(msg, msgType, sock);
        CHECK((respLen = Receive(sock, buffer, BUFFER_LEN)), "Error reading from socket");
        if (respLen == 0) {
            perror("Server disconnected");
            exit(EXIT_FAILURE);
        }
        if ((buffer[0] - '0') == S_CONFIRM) {
            ci.setLogin(login);
            break;
        }
    }

    if (fork() == 0) {
        // In child process we are behaving as listener socket and write to chat log
        // or report errors to stderr
        //
        prctl(PR_SET_PDEATHSIG, SIGHUP);
        while (true) {
            CHECK((respLen = Receive(sock, buffer, BUFFER_LEN)), "Error reading from socket");
            if (respLen == 0) {
                perror("Server disconnected");
                exit(EXIT_FAILURE);
            }
            int type = buffer[0] - '0';
            if (type == S_ERROR) {
                std::cerr << "Server couldn't process your message\n";
            } else {
                std::string completeMessage;
                std::string sender;
                if (!ClientMessageProcessor::ParseChatMessage(
                        buffer,
                        respLen,
                        ci,
                        completeMessage,
                        sender
                    )) {
                    std::cerr << "Unknown package received from server\n";
                } else if (!completeMessage.empty()) {
                    if (sender == ci.getLogin()) {
                        sender = "** " + sender + " **";
                    }
                    chat << "[ " << sender << " ]\n";
                    chat << completeMessage << "\n\n";
                    chat.flush();
                }
            }
        }
    } else {
        // Here we read from stdin and send messages to server
        //
#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"
        while (true) {
            std::string text;
            std::getline(std::cin, text);
            std::vector<std::string> msgs;
            ClientMessageProcessor::PrepareChatMessage(msgs, text, ci);
            for (int i = 0; i < msgs.size(); i++) {
                Send(msgs[i], (i == (int) msgs.size() - 1 ? C_CHAT_MESSAGE_FINISHED : C_CHAT_MESSAGE), sock);
            }
        }
#pragma clang diagnostic pop
    }
}
