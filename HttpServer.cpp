//
// HttpServer.cpp
// Lightweight HTTP server for SIP call control
//

#include "HttpServer.h"
#include "SipServer.h"
#include "Utils/Log.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <algorithm>

HttpServer::HttpServer(const std::string &bindIp, int port)
    : mBindIp(bindIp), mPort(port) {
}

HttpServer::~HttpServer() {
    stop();
}

bool HttpServer::start() {
    mListenFd = socket(AF_INET, SOCK_STREAM, 0);
    if (mListenFd < 0) {
        LOGE("HTTP socket create failed: %s", strerror(errno));
        return false;
    }

    int reuse = 1;
    setsockopt(mListenFd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(mPort);
    if (mBindIp.empty() || mBindIp == "0.0.0.0") {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        inet_pton(AF_INET, mBindIp.c_str(), &addr.sin_addr);
    }

    if (bind(mListenFd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOGE("HTTP bind %s:%d failed: %s", mBindIp.c_str(), mPort, strerror(errno));
        close(mListenFd);
        mListenFd = -1;
        return false;
    }

    if (listen(mListenFd, 16) < 0) {
        LOGE("HTTP listen failed: %s", strerror(errno));
        close(mListenFd);
        mListenFd = -1;
        return false;
    }

    mRunning = true;
    mThread = std::thread(&HttpServer::acceptLoop, this);

    LOGI("[HttpServer] Listening on %s:%d", mBindIp.c_str(), mPort);
    return true;
}

void HttpServer::stop() {
    if (!mRunning) return;
    mRunning = false;

    if (mListenFd >= 0) {
        shutdown(mListenFd, SHUT_RDWR);
        close(mListenFd);
        mListenFd = -1;
    }
    if (mThread.joinable()) mThread.join();
}

void HttpServer::acceptLoop() {
    while (mRunning) {
        struct sockaddr_in clientAddr{};
        socklen_t clientLen = sizeof(clientAddr);
        int clientFd = accept(mListenFd, (struct sockaddr *)&clientAddr, &clientLen);
        if (clientFd < 0) {
            if (!mRunning) break;
            continue;
        }

        // 设置 recv 超时 5 秒
        struct timeval tv{};
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(clientFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        handleClient(clientFd);
        close(clientFd);
    }
}

void HttpServer::handleClient(int clientFd) {
    std::string raw;
    char buf[4096];

    while (raw.size() < MAX_REQUEST_SIZE) {
        ssize_t n = recv(clientFd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        raw.append(buf, n);

        // 检查是否收到完整 header（\r\n\r\n）
        size_t headerEnd = raw.find("\r\n\r\n");
        if (headerEnd == std::string::npos) continue;

        // 解析 Content-Length
        size_t clPos = raw.find("Content-Length:");
        if (clPos != std::string::npos) {
            size_t valStart = clPos + 15;
            while (valStart < raw.size() && raw[valStart] == ' ') valStart++;
            size_t valEnd = raw.find("\r\n", valStart);
            int contentLen = 0;
            if (valEnd != std::string::npos) {
                contentLen = atoi(raw.substr(valStart, valEnd - valStart).c_str());
            }
            size_t bodyStart = headerEnd + 4;
            if (raw.size() >= bodyStart + contentLen) {
                break; // 完整请求已收到
            }
        } else {
            break; // 无 body，header 完整即可
        }
    }

    std::string method, path, body;
    std::map<std::string, std::string> params;
    if (!parseRequest(raw, method, path, body, params)) {
        std::string resp = buildResponse(400, "text/plain", "Bad Request");
        send(clientFd, resp.c_str(), resp.size(), 0);
        return;
    }

    // 把 body 作为 params["body"]
    if (!body.empty()) {
        params["body"] = body;
    }

    LOGI("[HttpServer] %s %s", method.c_str(), path.c_str());

    std::string result = route(method, path, params);
    std::string resp = buildResponse(200, "application/json", result);
    send(clientFd, resp.c_str(), resp.size(), 0);
}

bool HttpServer::parseRequest(const std::string &raw, std::string &method, std::string &path,
                               std::string &body, std::map<std::string, std::string> &params) {
    // 请求行: METHOD /path?query HTTP/1.1
    size_t lineEnd = raw.find("\r\n");
    if (lineEnd == std::string::npos) return false;

    std::string requestLine = raw.substr(0, lineEnd);
    size_t sp1 = requestLine.find(' ');
    if (sp1 == std::string::npos) return false;
    size_t sp2 = requestLine.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) return false;

    method = requestLine.substr(0, sp1);
    std::string uri = requestLine.substr(sp1 + 1, sp2 - sp1 - 1);

    // 分离 path 和 query string
    size_t qpos = uri.find('?');
    if (qpos != std::string::npos) {
        path = uri.substr(0, qpos);
        std::string query = uri.substr(qpos + 1);
        // 解析 key=value&...
        size_t start = 0;
        while (start < query.size()) {
            size_t eq = query.find('=', start);
            size_t amp = query.find('&', start);
            if (eq == std::string::npos) break;
            std::string key = query.substr(start, eq - start);
            std::string val;
            if (amp != std::string::npos) {
                val = query.substr(eq + 1, amp - eq - 1);
                start = amp + 1;
            } else {
                val = query.substr(eq + 1);
                start = query.size();
            }
            params[key] = val;
        }
    } else {
        path = uri;
    }

    // 提取 body
    size_t headerEnd = raw.find("\r\n\r\n");
    if (headerEnd != std::string::npos) {
        body = raw.substr(headerEnd + 4);
    }

    return true;
}

std::string HttpServer::route(const std::string &method, const std::string &path,
                               const std::map<std::string, std::string> &params) {
    if (path == "/invite" && method == "POST") {
        // 参数: device=340200000013200000024
        auto it = params.find("device");
        if (it == params.end()) {
            return R"({"code":1,"msg":"missing param: device"})";
        }
        std::string device = it->second;

        if (!mSipServer) {
            return R"({"code":1,"msg":"sip server not ready"})";
        }

        int ret = mSipServer->httpInvite(device);
        if (ret == 0) {
            return R"({"code":0,"msg":"invite sent"})";
        } else {
            return R"({"code":1,"msg":"invite failed"})";
        }
    }
    else if (path == "/bye" && method == "POST") {
        auto it = params.find("device");
        if (it == params.end()) {
            return R"({"code":1,"msg":"missing param: device"})";
        }
        std::string device = it->second;

        if (!mSipServer) {
            return R"({"code":1,"msg":"sip server not ready"})";
        }

        int ret = mSipServer->httpBye(device);
        if (ret == 0) {
            return R"({"code":0,"msg":"bye sent"})";
        } else {
            return R"({"code":1,"msg":"bye failed"})";
        }
    }
    else if (path == "/devices" && method == "GET") {
        if (!mSipServer) {
            return R"({"code":1,"msg":"sip server not ready"})";
        }
        return mSipServer->httpListDevices();
    }
    else {
        return R"({"code":1,"msg":"unknown endpoint"})";
    }
}

std::string HttpServer::buildResponse(int code, const std::string &contentType, const std::string &body) {
    const char *statusText = "OK";
    if (code == 400) statusText = "Bad Request";
    else if (code == 404) statusText = "Not Found";
    else if (code == 500) statusText = "Internal Server Error";

    char header[1024];
    snprintf(header, sizeof(header),
             "HTTP/1.1 %d %s\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n"
             "Access-Control-Allow-Origin: *\r\n"
             "\r\n",
             code, statusText, contentType.c_str(), body.size());

    return std::string(header) + body;
}
