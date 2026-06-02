//
// Created bxc on 2022/11/25.
//

#ifndef BXC_SIPSERVER_SIPSERVER_H
#define BXC_SIPSERVER_SIPSERVER_H
extern "C" {
#include <osip2/osip_mt.h>
#include <eXosip2/eXosip.h>
}
#include <map>
#include <deque>
#include <string>
#include <atomic>
#include <chrono>
#include <mutex>

class RtpReceiver;

class ServerInfo {
public:
    ServerInfo(const char *ua,const char *nonce, const char *ip, int port, int rtpPortBase, int httpPort,
                        const char *sipId, const char *sipRealm, const char *sipPass, int sipTimeout, int sipExpiry):
                        mUa(ua),
                        mNonce(nonce),mIp(ip ? ip : ""),mPort(port),mSipId(sipId),
                        mSipRealm(sipRealm),mSipPass(sipPass),mSipTimeout(sipTimeout),
                        mSipExpiry(sipExpiry),mRtpPortBase(rtpPortBase),mHttpPort(httpPort){}
    ~ServerInfo() = default;
public:
    const char *getUa() const{
        return mUa;
    }
    const char * getNonce() const{
        return mNonce;
    }
    const std::string & getIp() const{
        return mIp;
    }
    void setIp(const std::string &ip) {
        mIp = ip;
    }
    int getPort() const {
        return mPort;
    }
    int getRtpPortBase() const {
        return mRtpPortBase;
    }
    int getHttpPort() const {
        return mHttpPort;
    }
    const char * getSipId() const{
        return mSipId;
    }
    const char * getSipRealm() const{
        return mSipRealm;
    }
    const char * getSipPass() const{
        return mSipPass;
    }
    int getTimeout() const {
        return mSipTimeout;
    }
    int getExpiry() const {
        return mSipExpiry;
    }

private:
    const char *mUa;
    const char *mNonce;//SIP服务随机数值
    std::string mIp;  //SIP服务IP，支持自动检测后更新
    int         mPort;//SIP服务端口
    const char *mSipId; //SIP服务器ID
    const char *mSipRealm;//SIP服务器域
    const char *mSipPass;//SIP password
    int mSipTimeout; //SIP timeout
    int mSipExpiry;// SIP到期
    int mRtpPortBase; // RTP起始端口
    int mHttpPort;   // HTTP服务端口

};

class Client {
public:
    Client(const std::string &ip, int port, const std::string &device) :
            mIp(ip),
            mPort(port),
            mDevice(device),
            mIsReg(false){
    }
    ~Client() = default;
public:

    void setReg(bool isReg) {
        mIsReg = isReg;
    }
    const std::string & getDevice() const{
        return mDevice;
    }
    const std::string & getIp() const{
        return mIp;
    }
    int getPort() const{
        return mPort;
    }

private:
    std::string mIp;   // client ip
    int mPort;          // client port
    std::string mDevice;// 340200000013200000024
    bool mIsReg;
};


class SipServer {
public:
    explicit SipServer(ServerInfo *info);
    ~SipServer();
public:
    void loop();

    // HTTP API 入口
    int httpInvite(const std::string &device);
    int httpBye(const std::string &device);
    std::string httpListDevices();

private:
    int init_sip_server();
    int sip_event_handle(eXosip_event_t *evtp);

    void response_message_answer(eXosip_event_t *evtp,int code);
    void response_register(eXosip_event_t *evtp);
    void response_register_401unauthorized(eXosip_event_t *evt);
    void response_message(eXosip_event_t *evtp);
    void response_invite_ack(eXosip_event_t *evtp);
    int request_bye(const std::string &device);
    int request_invite(const std::string &device, const std::string &sdpPort, const std::string &sdpRtcpPort);
    int request_record_info(const char *device, const char *userIp, int userPort,
                            const char *startTime, const char *endTime);
    int parse_xml(const char* data, const char* s_mark, bool with_s_make, const char* e_mark, bool with_e_make, char* dest);
    void dump_request(eXosip_event_t *evtp);
    void dump_response(eXosip_event_t *evtp);
    void enqueue_record_query(const char *device, const char *userIp, int userPort);
    void process_pending_record_queries();
    std::string build_record_query_time(bool startOfDay) const;
    int next_sn();
    int allocRtpPort();
    void releaseRtpPort(int port);
    void stopRtpReceiver(const std::string &device);

    struct PendingRecordQuery {
        std::string device;
        std::string ip;
        int port;
        std::chrono::steady_clock::time_point executeAt;
    };

    struct CallSession {
        int cid{-1};
        int did{-1};
        int rtpPort{0};
        int rtcpPort{0};
        RtpReceiver *receiver{nullptr};
    };

private:
    bool mQuit;
    struct eXosip_t *mSipCtx;
    ServerInfo *mInfo;
    std::atomic<int> mSn{1};
    std::atomic<int> mNextRtpPort{0};

    std::map<std::string, Client *> mClientMap;// <DeviceID,SipClient>
    std::map<std::string, CallSession> mCallMap;// <DeviceID, CallSession>
    std::mutex mCallMutex;

    std::deque<PendingRecordQuery> mPendingRecordQueries;
    int clearClientMap();
    Client * getClientByDevice(const char * device);
};


#endif //BXC_SIPSERVER_SIPSERVER_H
