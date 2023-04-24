#include "sha-1.h"
#include <iostream>
#include "winsock2.h"
#include <ws2tcpip.h>
#include <vector>
#include <iomanip>
#include <fstream>
#include <dirent.h>
#include <sys/stat.h>

#define DEFAULT_PORT "12"
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
    snprintf(file_path, PATH_MAX, "%s%s", dir_path.c_str(), ent->d_name);
    if (dir_path[dir_path.length() - 1] != '/') {
        error = "You don't enter a directory";
        return true;
    }
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
    for (const auto &item: admins) {
        if (item == user)return true;
    }
    error = "Username/password is incorrect";
    return false;
}

bool PutBinary(SOCKET socket, string name, const string &second_name, string &error) {
    if (!second_name.empty())name = second_name;
    ofstream outputFile;
    outputFile.open(name, ios::binary);
    if (!outputFile) {
        error = "Error opening file.";
        return true;
    }
    //get info from socket
    char l[DEFAULT_BUF_LEN];
    int iResult = recv(socket, l, DEFAULT_BUF_LEN, 0);
    int len;
    if (iResult < 0) {
        error = "recv failed:\n" + WSAGetLastError();
        closesocket(socket);
        return true;
    }
    len = stoi(l);
    char res[len];
    iResult = recv(socket, res, len, 0);
    if (iResult < 0) {
        error = "recv failed:\n" + WSAGetLastError();
        closesocket(socket);
        return true;
    }
    outputFile.write(res, iResult);
    outputFile.close();
    return false;
}

bool Put(SOCKET socket, string name, const string &second_name, string &error) {
    if (!second_name.empty())name = second_name;
    ofstream outputFile;
    outputFile.open(name);
    if (!outputFile) {
        error = "Error opening file.";
        return true;
    }
    //get info from socket
    char l[DEFAULT_BUF_LEN];
    int iResult = recv(socket, l, DEFAULT_BUF_LEN, 0);
    int len;
    if (iResult < 0) {
        error = "recv failed:\n" + WSAGetLastError();
        closesocket(socket);
        return true;
    }
    len = stoi(l);
    char res[len];
    iResult = recv(socket, res, len, 0);
    if (iResult < 0) {
        error = "recv failed:\n" + WSAGetLastError();
        closesocket(socket);
        return true;
    }
    outputFile.write(res, iResult);
    outputFile.close();
    return false;
}

bool GetBinary(SOCKET socket, const string &name, string &error) {
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
    int iResult = send(socket, to_string(len).c_str(), to_string(len).length(), 0);
    if (iResult < 0) {
        error = "recv failed:\n" + WSAGetLastError();
        closesocket(socket);
        return true;
    }
    iResult = send(socket, l, len, 0);
    if (iResult < 0) {
        error = "recv failed:\n" + WSAGetLastError();
        closesocket(socket);
        return true;
    }
    inputFile.close();
    return false;
}

bool Get(SOCKET socket, const string &name, string &error) {
    ifstream inputFile;
    inputFile.open(name);
    if (!inputFile) {
        error = "Error opening file.";
        return true;
    }
    //get info from socket
    string l;
    int len = 0;
    string line;
    while (std::getline(inputFile, line)) {
        l += line + "\n";
        len += line.length() + 1;
    }
    int iResult = send(socket, to_string(len).c_str(), to_string(len).length(), 0);
    if (iResult < 0) {
        error = "recv failed:\n" + WSAGetLastError();
        closesocket(socket);
        return true;
    }
    iResult = send(socket, l.c_str(), len, 0);
    if (iResult < 0) {
        error = "recv failed:\n" + WSAGetLastError();
        closesocket(socket);
        return true;
    }
    inputFile.close();
    return false;
}

void BindSocket(SOCKET ListenSocket, SOCKET &DataSocket) {
    DataSocket = INVALID_SOCKET;
    // Accept a client socket
    DataSocket = accept(ListenSocket, NULL, NULL);
    if (DataSocket == INVALID_SOCKET) {
        printf("accept failed: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return;
    }

}

void ClientHandler(SOCKET ClientSocket) {
    vector<pair<string, string>> users;//all registered users
    string error;//message with error if something went wrong
    bool isError = false;
    pair<string, string> user;
    string directory = "./"; //current directory
    int iResult;
    bool isBinary = false;
    do {
        int len;
        char ls[DEFAULT_BUF_LEN];
        iResult = recv(ClientSocket, ls, DEFAULT_BUF_LEN, 0);
        if (iResult < 0) {
            error = "recv failed:\n" + WSAGetLastError();
            isError = true;
            closesocket(ClientSocket);
        }
        if (isError) {
            cout << error << endl;
            isError = false;
            continue;
        }

        len = stoi(ls);
        char buffer[len];
        iResult = recv(ClientSocket, buffer, len, 0);
        if (iResult < 0) {
            error = "recv failed:\n" + WSAGetLastError();
            isError = true;
            closesocket(ClientSocket);
        }
        if (isError) {
            cout << error << endl;
            isError = false;
            continue;
        }
        clenup(buffer, len);
        string command = buffer;
        if (command == "cd") {
            SOCKET DataSocket;
            BindSocket(ListenSocket, DataSocket);
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
            directory = buffer;
            closesocket(DataSocket);
        }
        else if (command == "dir") {
            SOCKET DataSocket;
            BindSocket(ListenSocket, DataSocket);
            vector<string> files;
            string filter;
            string res;
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
            filter = buffer;
            isError = Dir(directory, filter, files, error);
            if (isError) {
                cout << error << endl;
                closesocket(DataSocket);
                isError = false;
                continue;
            }
            makeACharArr(files, res);
            iResult = send(DataSocket, to_string(res.length()).c_str(), DEFAULT_BUF_LEN, 0);
            if (iResult < 0) {
                error = "send failed:\n" + WSAGetLastError();
                isError = true;
                closesocket(DataSocket);
            }
            if (isError) {
                cout << error << endl;
                isError = false;
                continue;
            }
            iResult = send(DataSocket, res.c_str(), res.length(), 0);
            if (iResult < 0) {
                error = "send failed:\n" + WSAGetLastError();
                isError = true;
                closesocket(DataSocket);
            }
            if (isError) {
                cout << error << endl;
                isError = false;
                continue;
            }
            closesocket(DataSocket);

        }
        else if (command == "put") {
            SOCKET DataSocket;
            BindSocket(ListenSocket, DataSocket);
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
            string name = buffer;
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
            string localName = buffer;
            if (!isBinary) {
                isError = Put(DataSocket, name, localName, error);
                if (isError) {
                    cout << error << endl;
                    closesocket(DataSocket);
                    isError = false;
                    continue;
                }
                closesocket(DataSocket);
            }
            else {
                isError = PutBinary(DataSocket, name, localName, error);
                if (isError) {
                    cout << error << endl;
                    closesocket(DataSocket);
                    isError = false;
                    continue;
                }
                closesocket(DataSocket);
            }

        }
        else if (command == "get") {
            SOCKET DataSocket;
            BindSocket(ListenSocket, DataSocket);
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
            string name = buffer;
            if (!isBinary) {
                isError = Get(DataSocket, name, error);
                if (isError) {
                    cout << error << endl;
                    isError = false;
                    closesocket(DataSocket);
                    continue;
                }
                closesocket(DataSocket);
            }
            else {
                isError = GetBinary(DataSocket, name, error);
                if (isError) {
                    cout << error << endl;
                    isError = false;
                    closesocket(DataSocket);
                    continue;
                }
                closesocket(DataSocket);
            }

        }
        else if (command == "ascii") {
            isBinary = false;

        }
        else if (command == "binary") {
            isBinary = true;
        }
        else if (command == "user") {
            SOCKET DataSocket;
            BindSocket(ListenSocket, DataSocket);
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
            user.second = "";
            user.first = buffer;
            closesocket(DataSocket);

        }
        else if (command == "lcd") {
            //Some Easter eggs
        }
        else if (command == "pwd") {
            SOCKET DataSocket;
            BindSocket(ListenSocket, DataSocket);
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
            iResult = send(DataSocket, to_string(res.length()).c_str(), DEFAULT_BUF_LEN, 0);
            if (iResult < 0) {
                error = "send failed:\n" + WSAGetLastError();
                isError = true;
                closesocket(DataSocket);
            }
            if (isError) {
                cout << error << endl;
                isError = false;
                continue;
            }
            iResult = send(DataSocket, res.c_str(), res.length(), 0);
            if (iResult < 0) {
                error = "send failed:\n" + WSAGetLastError();
                isError = true;
                closesocket(DataSocket);
            }
            if (isError) {
                cout << error << endl;
                isError = false;
                continue;
            }
            closesocket(DataSocket);

        }
        else if (command == "login") {
            SOCKET DataSocket;
            BindSocket(ListenSocket, DataSocket);
            vector<pair<string, string>> users;
            isError = GetAdmins(users, error);
            if (isError) {
                cout << error << endl;
                isError = false;
                closesocket(DataSocket);
                continue;
            }
            isError = isUserValid(users, user, error);
            if (!isError) {
                error = "Login successful";
            }
            iResult = send(DataSocket, to_string(error.length()).c_str(), DEFAULT_BUF_LEN, 0);
            if (iResult < 0) {
                error = "send failed:\n" + WSAGetLastError();
                isError = true;
                closesocket(DataSocket);
            }
            if (isError) {
                cout << error << endl;
                isError = false;
                continue;
            }
            iResult = send(DataSocket, error.c_str(), error.length(), 0);
            if (iResult < 0) {
                error = "send failed:\n" + WSAGetLastError();
                isError = true;
                closesocket(DataSocket);
            }
            if (isError) {
                cout << error << endl;
                isError = false;
                continue;
            }
            closesocket(DataSocket);

        }
        else if (command == "password") {
            SOCKET DataSocket;
            BindSocket(ListenSocket, DataSocket);
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
            closesocket(DataSocket);
        }

    } while (iResult > 0);
    closesocket(ClientSocket);
}
bool Recive(string& res,SOCKET DataSocket){
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
        cout<<"recv failed:\n" << WSAGetLastError();
        closesocket(DataSocket);
        return true;


    }
    clenup(buffer, len);
    res = buffer;
    return false;
}
bool Send(const string& string, SOCKET DataSocket){
    int iResult=send(DataSocket,to_string(string.length()).c_str(),DEFAULT_BUF_LEN,0);
    if (iResult < 0) {
        cout<< "recv failed:\n" << WSAGetLastError();
        closesocket(DataSocket);
        return true;
    }
    iResult=send(DataSocket,string.c_str(),string.length(),0);
    if (iResult < 0) {
        cout<< "recv failed:\n" << WSAGetLastError();
        closesocket(DataSocket);
        return true;
    }
    return false;
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

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;
// Resolve the local address and port to be used by the server
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed: %d\n", iResult);
        WSACleanup();
        return 1;
    }
    SOCKET ListenSocket = INVALID_SOCKET;

    // Create a SOCKET for the server to listen for client connections
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        printf("Error at socket(): %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Set up the TCP listening socket
    iResult = bind(ListenSocket, result->ai_addr, (int) result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR) {
        printf("Listen failed with error: %ld\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    SOCKET ClientSocket = INVALID_SOCKET;
    // Accept a client socket
    ClientSocket = accept(ListenSocket, NULL, NULL);
    if (ClientSocket == INVALID_SOCKET) {
        printf("accept failed: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    ClientHandler(ClientSocket);
    return 0;
}

