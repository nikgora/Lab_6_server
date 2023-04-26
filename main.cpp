#include "sha-1.h"
#include <iostream>
#include "winsock2.h"
#include <ws2tcpip.h>
#include <vector>
#include <iomanip>
#include <fstream>
#include <dirent.h>
#include <sys/stat.h>

#define DEFAULT_BUF_LEN 1024

using namespace std;

struct addrinfo *result = NULL,
        *ptr = NULL,
        hints;

void clenup(char *recvbuf, int len) {
    for (int i = len; i < strlen(recvbuf); i++) {
        recvbuf[i] = '\000';
    }
}

void makeACharArr(vector<string> strings, string &res) {
    for (auto e: strings) {
        string str;
        str = e;
        res += str;
        res += "\n";
    }
    res[res.length() - 1] = '\000';
}

bool GetAdmins(vector<pair<string, string>> &pVector, string &error) {//read all registrated user from file
    ifstream inputFile;
    inputFile.open("../User data.txt");
    if (!inputFile) {
        error = "Error opening file.";
        return true;
    }
    string line;
    while (getline(inputFile, line)) {
        // create a stringstream from the line
        stringstream ss(line);
        // read the first and second words from the stringstream
        string word1, word2;
        ss >> word1 >> word2;
        // process the two words as needed
        pair<string, string> temp;
        temp.first = word1;
        temp.second = word2;
        pVector.push_back(temp);
    }
    inputFile.close();
    return false;
}

bool endWith(const string &string1, const string &string2) {
    for (int i = 0; i < string2.length(); ++i) {
        if (string1[string1.length() - string2.length() + i + 1] != string2[i])return false;
    }
    return true;
}

bool Dir(string dir_path, string &filter, vector<string> &files, string &error) {

    if (filter.empty())
        filter = "*";
    DIR *dir;
    struct dirent *ent;
    struct stat st;
    char file_path[PATH_MAX];
    if (dir_path[dir_path.length() - 1] != '/') {
        error = "You don't enter a directory";
        return true;
    }
    //snprintf(file_path, PATH_MAX, "%s%s", dir_path.c_str(), ent->d_name);
    dir = opendir(dir_path.c_str());
    if (dir == NULL) {
        error = "Error opening directory";
        return true;
    }
    for (int i = 0; i < filter.length() - 1; ++i) {
        filter[i] = filter[i + 1];
    }
    filter[filter.length() - 1] = '\0';
    // loop through all files in the directory
    while ((ent = readdir(dir)) != NULL) {
        // construct the full path to the file
        char file_path[PATH_MAX];
        snprintf(file_path, PATH_MAX, "%s%s", dir_path.c_str(), ent->d_name);
        // get the file status
        if (stat(file_path, &st) == -1) {
            continue;
        }
        if (S_ISREG(st.st_mode) && endWith(file_path, filter)) {
            string temp = file_path;
            files.push_back(temp);
        }
    }
    return false;
}

bool Pwd(string dir_path, vector<string> &dirs, string &error) {//get all files from directory
    DIR *dir;
    struct dirent *ent;
    struct stat st;
    if (dir_path[dir_path.length() - 1] != '/') {
        error = "You don't enter a directory";
        return true;
    }
    // open the directory
    dir = opendir(dir_path.c_str());
    if (dir == NULL) {
        error = "Error opening directory";
        return true;
    }
    // loop through all files in the directory
    while ((ent = readdir(dir)) != NULL) {
        // construct the full path to the file
        char file_path[PATH_MAX];
        snprintf(file_path, PATH_MAX, "%s%s", dir_path.c_str(), ent->d_name);
        // get the file status
        if (stat(file_path, &st) == -1) {
            continue;
        }
        string temp = file_path;
        dirs.push_back(temp);
    }
    // close the directory
    closedir(dir);
    return false;
}

bool isUserValid(const vector<pair<string, string>> &admins, const pair<string, string> &user,
                 string &error) {//get all users that registrated and check with user that are trying to login
    string userFirst = user.first;
    string userSecond = user.second;
    for (pair<string, string> item: admins) {
        string itemFirst = item.first;
        string itemSecond = item.second;

        if (itemFirst == userFirst && itemSecond == userSecond)return true;
    }
    error = "Username/password is incorrect";
    return false;
}

bool Recive(string &res, SOCKET DataSocket) {
    char ls[DEFAULT_BUF_LEN];
    int iResult = recv(DataSocket, ls, DEFAULT_BUF_LEN, 0);
    if (iResult < 0) {
        cout << "recv failed:\n" << WSAGetLastError();
        closesocket(DataSocket);
        return true;
    }
    int len = stoi(ls);
    char buffer[len];
    iResult = recv(DataSocket, buffer, len, 0);
    if (iResult < 0) {
        cout << "recv failed:\n" << WSAGetLastError();
        closesocket(DataSocket);
        return true;

    }
    clenup(buffer, len);
    res = buffer;
    return false;
}

bool Send(const string &string, SOCKET DataSocket) {
    int iResult = send(DataSocket, to_string(string.length()).c_str(), DEFAULT_BUF_LEN, 0);
    if (iResult < 0) {
        cout << "recv failed:\n" << WSAGetLastError();
        closesocket(DataSocket);
        return true;
    }
    iResult = send(DataSocket, string.c_str(), string.length(), 0);
    if (iResult < 0) {
        cout << "recv failed:\n" << WSAGetLastError();
        closesocket(DataSocket);
        return true;
    }
    return false;
}

bool GetBinary(SOCKET socket, string name, const string &second_name, string &error) {
    if (!second_name.empty())name = second_name;
    ofstream outputFile;
    outputFile.open(name, ios::binary);
    if (!outputFile) {
        error = "Error opening file.";
        return true;
    }
    string res;
    if (Recive(res, socket)) return true;
    outputFile.write(res.c_str(), res.length());
    outputFile.close();
    return false;
}

bool Get(SOCKET socket, string name, const string &second_name, string &error) {
    if (!second_name.empty())name = second_name;
    string res;
    if (Recive(res, socket))return true;
    ofstream outputFile;
    outputFile.open(name);
    if (!outputFile) {
        error = "Error opening file.";
        return true;
    }

    outputFile.write(res.c_str(), res.length());
    outputFile.close();
    return false;
}

bool PutBinary(SOCKET socket, const string &name, string &error) {
    ifstream inputFile;
    inputFile.open(name, ios::binary);
    if (!inputFile) {
        error = "Error opening file.";
        return true;
    }
    //get info from socket
    char *l;
    inputFile.seekg(0, ios::end);
    int len = inputFile.tellg();
    inputFile.seekg(0, ios::beg);

    inputFile.read(l, len);
    if (Send(l, socket))return true;
    inputFile.close();
    return false;
}

bool Put(SOCKET socket, const string &name, string &error) {
    ifstream inputFile;
    inputFile.open(name);
    if (!inputFile) {
        error = "Error opening file.";
        return true;
    }
    //get info from socket
    string l;
    string line;
    while (std::getline(inputFile, line)) {
        l += line + "\n";
    }
    inputFile.close();
    if (Send(l, socket))return true;
    return false;
}

bool BindSocket(SOCKET &DataSocket, const string &port) {

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;
// Resolve the local address and port to be used by the server
    int iResult = getaddrinfo(NULL, port.c_str(), &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed: %d\n", iResult);
        WSACleanup();
        return true;
    }
    SOCKET ListenSocket = INVALID_SOCKET;

    // Create a SOCKET for the server to listen for client connections
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        printf("Error at socket(): %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return true;
    }

    // Set up the TCP listening socket
    iResult = bind(ListenSocket, result->ai_addr, (int) result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return true;
    }
    if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR) {
        printf("Listen failed with error: %ld\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return true;
    }

    // Accept a client socket
    DataSocket = accept(ListenSocket, NULL, NULL);
    if (DataSocket == INVALID_SOCKET) {
        printf("accept failed: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return true;
    }
    closesocket(ListenSocket);
    return false;

}

void ClientHandler(SOCKET &ClientSocket) {
    vector<pair<string, string>> users;//all registered users
    string error;//message with error if something went wrong
    bool isError = false;
    pair<string, string> user;
    string directory = "./"; //current directory
    int iResult = 0;
    bool isBinary = false;
    bool isOpen = false;
    string command;
    SOCKET DataSocket = INVALID_SOCKET;
    do {
        if (Recive(command, ClientSocket)) {
            iResult = -1;
            continue;
        }
        cout << command << endl;
        if (command == "cd" && isOpen) {
            if (Recive(directory, DataSocket)) {
                iResult = -1;
                continue;
            }
        }
        else if (command == "dir" && isOpen) {

            vector<string> files;
            string filter;
            string res;
            if (Recive(filter, DataSocket)) {
                iResult = -1;
                continue;
            }
            isError = Dir(directory, filter, files, error);
            if (isError) {
                cout << error << endl;
                closesocket(DataSocket);
                isError = false;
                continue;
            }
            makeACharArr(files, res);
            if (Send(res, DataSocket)) {
                iResult = -1;
                continue;
            }

        }
        else if (command == "put" && isOpen) {
            string name, local_name;
            if (Recive(name, DataSocket)) {
                iResult = -1;
                continue;
            }
            if (Recive(local_name, DataSocket)) {
                iResult = -1;
                continue;
            }
            if (isBinary) {
                isError = GetBinary(DataSocket, name, local_name, error);
                if (isError) {
                    cout << error << endl;
                    closesocket(DataSocket);
                    isError = false;
                    iResult = -1;
                    continue;
                }
            }
            else {
                isError = Get(DataSocket, name, local_name, error);
                if (isError) {
                    cout << error << endl;
                    closesocket(DataSocket);
                    isError = false;
                    iResult = -1;
                    continue;
                }
            }

        }
        else if (command == "get" && isOpen) {

            string name;
            if (Recive(name, DataSocket)) {
                iResult = -1;
                continue;
            }
            if (isBinary) {
                isError = PutBinary(DataSocket, name, error);
                if (isError) {
                    cout << error << endl;
                    closesocket(DataSocket);
                    isError = false;
                    iResult = -1;
                    continue;
                }
            }
            else {
                isError = Put(DataSocket, name, error);
                if (isError) {
                    cout << error << endl;
                    closesocket(DataSocket);
                    isError = false;
                    iResult = -1;
                    continue;
                }
            }
        }
        else if (command == "ascii" && isOpen) {
            isBinary = false;
        }
        else if (command == "binary" && isOpen) {
            isBinary = true;
        }
        else if (command == "pwd" && isOpen) {
            vector<string> dirs;
            isError = Pwd(directory, dirs, error);
            if (isError) {
                closesocket(DataSocket);
                cout << error << endl;
                isError = false;
                continue;
            }
            string res;
            makeACharArr(dirs, res);

            if (Send(res, DataSocket)) {
                iResult = -1;
                continue;
            }

        }
        else if ((command == "login" || command == "user") && isOpen) {
            vector<pair<string, string>> users;
            isError = GetAdmins(users, error);//get list of all users include anonym
            if (isError) {
                cout << error << endl;
                isError = false;
                continue;
            }
            string us, pas;
            if (Recive(us, DataSocket)) {
                iResult = -1;
                continue;
            }
            user.first = us;
            if (Recive(pas, DataSocket)) {
                iResult = -1;
                continue;
            }
            user.second = pas;
            isError = !isUserValid(users, user, error);
            if (!isError) {
                error = "Login successful";
            }

            if (Send(error, DataSocket)) {
                iResult = -1;
                continue;
            }

        }
            /*
            else if (command == "password" && isOpen) {

                iResult = recv(DataSocket, ls, DEFAULT_BUF_LEN, 0);
                if (iResult < 0) {
                    error = "recv failed:\n" + WSAGetLastError();
                    isError = true;
                    closesocket(DataSocket);
                }
                if (isError) {
                    cout << error << endl;
                    isError = false;
                    continue;
                }
                len = stoi(ls);
                realloc(buffer, len);
                iResult = recv(DataSocket, buffer, len, 0);
                if (iResult < 0) {
                    error = "recv failed:\n" + WSAGetLastError();
                    isError = true;
                    closesocket(DataSocket);
                }
                if (isError) {
                    cout << error << endl;
                    isError = false;
                    continue;
                }

                clenup(buffer, len);
                user.second = buffer;
            }
             */
        else if (command == "open") {
            if (BindSocket(DataSocket, "13")) {
                iResult = -1;
                continue;
            }
            isOpen = true;
        }
        else if (command == "close" && isOpen) {
            if(isOpen)closesocket(DataSocket);
            isBinary = false;
            isOpen = false;
        }
        else if (command == "quit" && isOpen) {
            closesocket(DataSocket);
            isBinary = false;
            isOpen = false;
            iResult = -1;
        }
    } while (iResult >= 0);
    closesocket(ClientSocket);
}

int main() {
    WSADATA wsaData;
    char recvbuf[DEFAULT_BUF_LEN];
    int iResult, iSendResult;
    int recvbuflen = DEFAULT_BUF_LEN;
// Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed: %d\n", iResult);
        return 1;

    }
    SOCKET ClientSocket = INVALID_SOCKET;
    if (BindSocket(ClientSocket, "12"))return 1;
    ClientHandler(ClientSocket);
    return 0;
}

