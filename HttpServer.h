//
// HttpServer.h
// Lightweight HTTP server for SIP call control
//

#ifndef BXC_SIPSERVER_HTTPSERVER_H
#define BXC_SIPSERVER_HTTPSERVER_H

#include <string>
#include <atomic>
#include <thread>
#include <map>
#include <mutex>
#include <functional>

class SipServer;

struct HttpRoute {
    std::string method;  // "GET", "POST", etc.
    std::string path;    // "/invite", "/bye", etc.
    std::function<std::string(const std::map<std::string, std::string> &params)> handler;
};

class HttpServer {
public:
    HttpServer(const std::string &bindIp, int port);
    ~HttpServer();

    void setSipServer(SipServer *sip) { mSipServer = sip; }

    bool start();
    void stop();

private:
    void acceptLoop();
    void handleClient(int clientFd);
    bool parseRequest(const std::string &raw, std::string &method, std::string &path,
                      std::string &body, std::map<std::string, std::string> &params);
    std::string route(const std::string &method, const std::string &path,
                      const std::map<std::string, std::string> &params);
    std::string buildResponse(int code, const std::string &contentType, const std::string &body);

    std::string mBindIp;
    int mPort;
    int mListenFd{-1};
    std::atomic<bool> mRunning{false};
    std::thread mThread;
    SipServer *mSipServer{nullptr};

    static constexpr size_t MAX_REQUEST_SIZE = 65536;
};

#endif // BXC_SIPSERVER_HTTPSERVER_H
