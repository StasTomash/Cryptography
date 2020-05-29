#include <vector>
#include <cstring>
#include <sys/types.h>
#include <cstdlib>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cstdio>
#include <cerrno>
#include <unistd.h>
#include <thread>
#include "ServerUtils.h"

#define PORT 8888
#define MAX_CLIENTS 30
#define BUFFER_SIZE 65535

void Send(const std::string& msg, int type, int socket) {
    char* buff = new char[msg.length() + 2];
    sprintf(buff, "%d", type);
    strcpy(buff+1, msg.c_str());
    buff[msg.length()+1] = '\0';
    std::cout << "Sending " << buff << " to " << socket << "\n";
    send(socket, buff, strlen(buff), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

int Receive(int socket, char* buff, int buffSize) {
    memset(buff, 0, buffSize);
    int len = recv(socket, buff, buffSize, 0);
    std::cout << "Received: " << buff << " from " << socket << "\n";
    return len;
}

int main(int argc, char** argv) {
    int optionTrue = 1;
    int masterSocket;
    fd_set fdSet;
    std::vector<int> clientSockets(MAX_CLIENTS);
    struct sockaddr_in address{};
    ServerInfo serverInfo{};

    // Creating a master socket
    //
    if ((masterSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        perror("Server failed to start");
        exit(EXIT_FAILURE);
    }
    // Allowing master socket to have multiple connections
    //
    if (setsockopt(masterSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&optionTrue, sizeof(optionTrue)) < 0) {
        perror("Failed to allow multiple connections");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    socklen_t addrLen = sizeof(address);

    // Binding socket to localhost:PORT
    //
    CHECK(bind(masterSocket, (struct sockaddr*)&address, sizeof(address)), "Error binding master socket to port");

    printf("Created listener on port %d \n", PORT);
    CHECK(listen(masterSocket, MAX_CLIENTS), "Can't listen to clients");

    while (true) {
        FD_ZERO(&fdSet);
        FD_SET(masterSocket, &fdSet);
        // select needs to know maximal of socket descriptors
        int maxFd = masterSocket;

        for (size_t i = 0; i < MAX_CLIENTS; i++) {
            if (clientSockets[i] > 0) {
                FD_SET(clientSockets[i], &fdSet);
                maxFd = std::max(maxFd, clientSockets[i]);
            }
        }

        int activity = select(maxFd + 1, &fdSet, nullptr, nullptr, nullptr);
        if ((activity < 0) && (errno!=EINTR)) {
            printf("Select registered bad activity");
            continue;
        }
        if (FD_ISSET(masterSocket, &fdSet)) {
            int newSocket;
            CHECK((newSocket = accept(masterSocket, (struct sockaddr*)&address, &addrLen)), "Error accepting connection");
            printf("Connected %d %s %d\n", newSocket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));
            for (auto& socket : clientSockets) {
                if (socket == 0) {
                    socket = newSocket;
                    std::string msg;
                    int msgType;
                    ServerMessageProcessor::PreparePublicKeyToSend(msg, msgType, serverInfo);
                    Send(msg, msgType, socket);
                    break;
                }
            }
        }
        for (auto& socket : clientSockets) {
            if (socket == 0) {
                continue;
            }
            char buffer[BUFFER_SIZE];
            size_t readBytes;
            if (FD_ISSET(socket, &fdSet)) {
                if ((readBytes = Receive(socket, buffer, BUFFER_SIZE)) == 0) {
                    // Empty string means that client disconnected
                    //
                    getpeername(socket, (struct sockaddr*)&address, &addrLen);
                    printf("Disconnected %d %s %d\n", socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));
                    close(socket);
                    serverInfo.closeConnection(socket);
                    socket = 0;
                } else {
                    if (!serverInfo.isRegistered(socket)) {
                        // Only message that server expects now is registration message
                        //
                        PersonInfo personInfo;
                        if (!ServerMessageProcessor::ParseRegistrationMessage(buffer, readBytes, personInfo, serverInfo)) {
                            Send("Wrong registration format", S_ERROR, socket);
                        } else {
                            serverInfo.registerConnection(socket, personInfo);
                            Send("", S_CONFIRM, socket);
                        }
                    } else {
                        // Means that client wants to send something to chat
                        //
                        buffer[readBytes] = '\0';
                        std::string completeMessage;
                        if (!ServerMessageProcessor::ParseChatMessage(
                                socket,
                                buffer,
                                readBytes,
                                serverInfo,
                                completeMessage
                            )) {
                            Send("Wrong message format / bad signature", S_ERROR, socket);
                        } else if (!completeMessage.empty()) {
                            for (auto otherSocket : clientSockets) {
                                if (otherSocket == 0) {
                                    continue;
                                }
                                std::vector<std::string> msgs;
                                std::string login = serverInfo.getPerson(socket).login;
                                ServerMessageProcessor::PrepareChatMessage(
                                        otherSocket,
                                        msgs,
                                        completeMessage,
                                        serverInfo,
                                        login
                                    );
                                for (int i = 0; i < msgs.size(); i++) {
                                    Send(msgs[i], (i == (int)msgs.size()-1 ? S_CHAT_MESSAGE_FINISHED : S_CHAT_MESSAGE), otherSocket);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
