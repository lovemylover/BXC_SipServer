//
// Created bxc on 2022/11/25.
//

#include "SipServer.h"
#include "RtpReceiver.h"

#ifndef WIN32
#include <arpa/inet.h>
#include <unistd.h>
#else
#include <WinSock2.h>
#endif

#pragma comment(lib, "ws2_32.lib")

#include <cstring>
#include <cstdio>
#include <ctime>
#include "Utils/Log.h"

extern "C"{
#include "Utils/HTTPDigest.h"
}

SipServer::SipServer(ServerInfo *info):
        mQuit(false),
        mSipCtx(nullptr),
        mInfo(info){
    LOGI("%s:%d",mInfo->getIp().c_str(),mInfo->getPort());
    mNextRtpPort = mInfo->getRtpPortBase();
#ifdef WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        LOGE("WSAStartup Error");
        return;
    }
#endif
}

SipServer::~SipServer() {
    LOGI("");
    // 停止所有 RTP receiver
    {
        std::lock_guard<std::mutex> lock(mCallMutex);
        for (auto &kv : mCallMap) {
            if (kv.second.receiver) {
                kv.second.receiver->stop();
                delete kv.second.receiver;
            }
        }
        mCallMap.clear();
    }
    this->clearClientMap();
#ifdef WIN32
    WSACleanup();
#endif
}

int SipServer::sip_event_handle(eXosip_event_t *evtp) {

    switch(evtp->type) {
        case EXOSIP_CALL_MESSAGE_NEW:
            LOGI("EXOSIP_CALL_MESSAGE_NEW type=%d", evtp->type);
            this->dump_request(evtp);
            this->dump_response(evtp);
            break;

        case EXOSIP_CALL_CLOSED:
            LOGI("EXOSIP_CALL_CLOSED type=%d",evtp->type);
            this->dump_request(evtp);
            this->dump_response(evtp);
            break;

        case EXOSIP_CALL_RELEASED:
            LOGI("EXOSIP_CALL_RELEASED type=%d", evtp->type);
            this->dump_request(evtp);
            this->dump_response(evtp);
            this->clearClientMap();
            break;

        case EXOSIP_MESSAGE_NEW:
            LOGI("EXOSIP_MESSAGE_NEW type=%d",evtp->type);

            if (MSG_IS_REGISTER(evtp->request)) {
                this->response_register(evtp);
            }
            else if (MSG_IS_MESSAGE(evtp->request)) {
                this->response_message(evtp);
            }
            else if(strncmp(evtp->request->sip_method, "BYE", 3) != 0){
                LOGE("unknown1");
            }
            else{
                LOGE("unknown2");
            }
            break;
        case EXOSIP_MESSAGE_ANSWERED:
            this->dump_request(evtp);
            break;
        case EXOSIP_MESSAGE_REQUESTFAILURE:
            LOGI("EXOSIP_MESSAGE_REQUESTFAILURE type=%d", evtp->type);
            this->dump_request(evtp);
            this->dump_response(evtp);
            break;
        case EXOSIP_CALL_INVITE:
            LOGI("EXOSIP_CALL_INVITE type=%d: The server receives the Invite request from client", evtp->type);
            break;
        case EXOSIP_CALL_PROCEEDING:
            LOGI("EXOSIP_CALL_PROCEEDING type=%d", evtp->type);
            this->dump_request(evtp);
            this->dump_response(evtp);
            break;
        case EXOSIP_CALL_ANSWERED:
            LOGI("EXOSIP_CALL_ANSWERED type=%d: device accepted INVITE", evtp->type);
            this->dump_request(evtp);
            this->dump_response(evtp);
            this->response_invite_ack(evtp);
            break;
        case EXOSIP_CALL_SERVERFAILURE:
            LOGI("EXOSIP_CALL_SERVERFAILURE type=%d", evtp->type);
            break;
        case EXOSIP_IN_SUBSCRIPTION_NEW:
            LOGI("EXOSIP_IN_SUBSCRIPTION_NEW type=%d", evtp->type);
            break;
        default:
            LOGI("type=%d unknown", evtp->type);
            break;
    }

    return 0;
}

int SipServer::init_sip_server() {
    mSipCtx = eXosip_malloc();
    if (!mSipCtx) {
        LOGE("eXosip_malloc error");
        return -1;
    }
    if (eXosip_init(mSipCtx)) {
        LOGE("eXosip_init error");
        return -1;
    }
    if (eXosip_listen_addr(mSipCtx, IPPROTO_UDP, nullptr, mInfo->getPort(), AF_INET, 0)) {
        LOGE("eXosip_listen_addr error");
        return -1;
    }

    // 自动检测本机 IP（如果配置的 IP 为空或无效）
    std::string localIp = mInfo->getIp();
    if (localIp.empty() || localIp == "0.0.0.0" || localIp == "127.0.0.1") {
        // 通过创建 UDP socket 连接外部地址来探测本机出口 IP
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock >= 0) {
            struct sockaddr_in dst{};
            dst.sin_family = AF_INET;
            dst.sin_port = htons(53); // DNS port，不需要真的通
            inet_pton(AF_INET, "8.8.8.8", &dst.sin_addr);
            if (connect(sock, (struct sockaddr *)&dst, sizeof(dst)) == 0) {
                struct sockaddr_in src{};
                socklen_t srcLen = sizeof(src);
                if (getsockname(sock, (struct sockaddr *)&src, &srcLen) == 0) {
                    char buf[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &src.sin_addr, buf, sizeof(buf));
                    localIp = buf;
                    mInfo->setIp(localIp);
                    LOGI("Auto-detected local IP: %s", localIp.c_str());
                }
            }
            close(sock);
        }
    }

    // 告诉 eXosip2 本机 IP，修复 Via/Contact 中的 999.999.999.999 占位符
    if (!localIp.empty()) {
        char ipv4[64];
        snprintf(ipv4, sizeof(ipv4), "%s:%d", localIp.c_str(), mInfo->getPort());
        eXosip_set_option(mSipCtx, EXOSIP_OPT_SET_IPV4_FOR_GATEWAY, ipv4);
        LOGI("Set SIP gateway IP: %s", ipv4);
    }

    eXosip_set_user_agent(mSipCtx, mInfo->getUa());
    if (eXosip_add_authentication_info(mSipCtx, mInfo->getSipId(),mInfo->getSipId(), mInfo->getSipPass(), NULL, mInfo->getSipRealm())){
        LOGE("eXosip_add_authentication_info error");
        return -1;
    }

    return 0;
}

void SipServer::loop() {

    if(this->init_sip_server() !=0 ){
        return;
    }
    while(!mQuit) {
        this->process_pending_record_queries();
        eXosip_event_t *evtp = eXosip_event_wait(mSipCtx, 0, 20);
        if (!evtp){
            eXosip_automatic_action(mSipCtx);
            osip_usleep(100000);
            continue;
        }
        eXosip_automatic_action(mSipCtx);
        this->sip_event_handle(evtp);
        eXosip_event_free(evtp);
    }
}

void SipServer::response_message_answer(eXosip_event_t *evtp,int code){

    int returnCode = 0 ;
    osip_message_t * pRegister = nullptr;
    returnCode = eXosip_message_build_answer (mSipCtx,evtp->tid,code,&pRegister);
    bool bRegister = false;
    if(pRegister){
        bRegister = true;
    }
    if (returnCode == 0 && bRegister)
    {
        eXosip_lock(mSipCtx);
        eXosip_message_send_answer (mSipCtx,evtp->tid,code,pRegister);
        eXosip_unlock(mSipCtx);
    }
    else{
        LOGE("code=%d,returnCode=%d,bRegister=%d",code,returnCode,bRegister);
    }

}

void SipServer::response_register(eXosip_event_t *evtp) {

    osip_authorization_t * auth = nullptr;
    osip_message_get_authorization(evtp->request, 0, &auth);

    if(auth && auth->username){

        char *method = NULL,
        *algorithm = NULL,
        *username = NULL,
        *realm = NULL,
        *nonce = NULL,
        *nonce_count = NULL,
        *uri = NULL;

        osip_contact_t *contact = nullptr;
        osip_message_get_contact (evtp->request, 0, &contact);

        method = evtp->request->sip_method;
        char calc_response[HASHHEXLEN];
        HASHHEX HA1, HA2 = "", Response;

#define SIP_STRDUP(field) if (auth->field) (field) = osip_strdup_without_quote(auth->field)

        SIP_STRDUP(algorithm);
        SIP_STRDUP(username);
        SIP_STRDUP(realm);
        SIP_STRDUP(nonce);
        SIP_STRDUP(nonce_count);
        SIP_STRDUP(uri);

        DigestCalcHA1(algorithm, username, realm, mInfo->getSipPass(), nonce, nonce_count, HA1);
        DigestCalcResponse(HA1, nonce, nonce_count, auth->cnonce, auth->message_qop, 0, method, uri, HA2, Response);

        HASHHEX temp_HA1;
        HASHHEX temp_response;
        DigestCalcHA1("REGISTER", username, mInfo->getSipRealm(), mInfo->getSipPass(), mInfo->getNonce(), NULL, temp_HA1);
        DigestCalcResponse(temp_HA1, mInfo->getNonce(), NULL, NULL, NULL, 0, method, uri, NULL, temp_response);
        memcpy(calc_response, temp_response, HASHHEXLEN);

        // 提取设备 IP: 优先从 Contact，失败从 Via 取
        std::string clientIp;
        int clientPort = 0;
        if (contact && contact->url && contact->url->host) {
            clientIp = contact->url->host;
            if (contact->url->port) {
                clientPort = atoi(contact->url->port);
            }
        }
        if (clientIp.empty()) {
            osip_via_t *via = nullptr;
            osip_message_get_via(evtp->request, 0, &via);
            if (via && via->host) {
                clientIp = via->host;
                if (via->port) {
                    clientPort = atoi(via->port);
                } else {
                    clientPort = 5060;
                }
            }
        }

        Client *client = new Client(clientIp, clientPort, username ? username : "");

        if (!memcmp(calc_response, Response, HASHHEXLEN)) {
            this->response_message_answer(evtp,200);
            LOGI("Camera registration success,ip=%s,port=%d,device=%s",client->getIp().c_str(),client->getPort(),client->getDevice().c_str());

            auto it = mClientMap.find(client->getDevice());
            if (it != mClientMap.end()) {
                delete it->second;
                it->second = client;
            } else {
                mClientMap.insert(std::make_pair(client->getDevice(),client));
            }

            this->enqueue_record_query(client->getDevice().c_str(), client->getIp().c_str(), client->getPort());

            // 不再自动发起 INVITE，等待 HTTP 接口调用

        } else {
            this->response_message_answer(evtp,401);
            LOGI("Camera registration error, ip=%s,port=%d,device=%s",client->getIp().c_str(),client->getPort(),client->getDevice().c_str());
            delete client;
        }

        osip_free(algorithm);
        osip_free(username);
        osip_free(realm);
        osip_free(nonce);
        osip_free(nonce_count);
        osip_free(uri);
    } else {
        response_register_401unauthorized(evtp);
    }

}

void SipServer::response_register_401unauthorized(eXosip_event_t *evtp) {

    char *dest = nullptr;
    osip_message_t * reg = nullptr;
    osip_www_authenticate_t * header = nullptr;

    osip_www_authenticate_init(&header);
    osip_www_authenticate_set_auth_type (header, osip_strdup("Digest"));
    osip_www_authenticate_set_realm(header,osip_enquote(mInfo->getSipRealm()));
    osip_www_authenticate_set_nonce(header,osip_enquote(mInfo->getNonce()));
    osip_www_authenticate_to_str(header, &dest);
    int ret = eXosip_message_build_answer (mSipCtx, evtp->tid, 401, &reg);
    if ( ret == 0 && reg != nullptr ) {
        osip_message_set_www_authenticate(reg, dest);
        osip_message_set_content_type(reg, "Application/MANSCDP+xml");
        eXosip_lock(mSipCtx);
        eXosip_message_send_answer (mSipCtx, evtp->tid,401, reg);
        eXosip_unlock(mSipCtx);
        LOGI("response_register_401unauthorized success");
    }else {
        LOGI("response_register_401unauthorized error");
    }

    osip_www_authenticate_free(header);
    osip_free(dest);

}

void SipServer::response_message(eXosip_event_t *evtp) {

    osip_body_t* body = nullptr;
    char CmdType[64] = {0};
    char DeviceID[64] = {0};
    osip_message_get_body(evtp->request, 0, &body);
    if(body){
        parse_xml(body->body, "<CmdType>", false, "</CmdType>", false, CmdType);
        parse_xml(body->body, "<DeviceID>", false, "</DeviceID>", false, DeviceID);
    }

    LOGI("CmdType=%s,DeviceID=%s", CmdType,DeviceID);

    if(!strcmp(CmdType, "Catalog")) {
        this->response_message_answer(evtp,200);
    }
    else if(!strcmp(CmdType, "RecordInfo")){
        char SumNum[32] = {0};
        parse_xml(body ? body->body : nullptr, "<SumNum>", false, "</SumNum>", false, SumNum);
        this->response_message_answer(evtp,200);
        LOGI("RecordInfo response: device=%s, sumNum=%s", DeviceID, SumNum);
        if (body && body->body) {
            LOGI("RecordInfo body:\n%s", body->body);
        }
    }
    else if(!strcmp(CmdType, "Keepalive")){
        this->response_message_answer(evtp,200);
        // 更新设备 IP/端口，确保 HTTP /invite 可用
        if (strlen(DeviceID) > 0) {
            std::string clientIp;
            int clientPort = 0;
            osip_contact_t *contact = nullptr;
            osip_message_get_contact(evtp->request, 0, &contact);
            if (contact && contact->url && contact->url->host) {
                clientIp = contact->url->host;
                if (contact->url->port) {
                    clientPort = atoi(contact->url->port);
                }
            } else {
                // Contact 没有就从 Via 头取
                osip_via_t *via = nullptr;
                osip_message_get_via(evtp->request, 0, &via);
                if (via && via->host) {
                    clientIp = via->host;
                    if (via->port) {
                        clientPort = atoi(via->port);
                    } else {
                        clientPort = 5060;
                    }
                }
            }
            if (!clientIp.empty() && clientPort > 0) {
                std::string deviceId(DeviceID);
                auto it = mClientMap.find(deviceId);
                if (it != mClientMap.end()) {
                    // 已注册，更新地址
                    delete it->second;
                    it->second = new Client(clientIp, clientPort, deviceId);
                    LOGI("Keepalive updated device=%s ip=%s port=%d", DeviceID, clientIp.c_str(), clientPort);
                } else {
                    // 未注册（可能注册过期但心跳还在），也加入管理
                    mClientMap[deviceId] = new Client(clientIp, clientPort, deviceId);
                    LOGI("Keepalive added device=%s ip=%s port=%d", DeviceID, clientIp.c_str(), clientPort);
                }
            }
        }
    }else{
        this->response_message_answer(evtp,200);
    }

}

void SipServer::response_invite_ack(eXosip_event_t *evtp){
    osip_message_t* msg = nullptr;
    int ret = eXosip_call_build_ack(mSipCtx, evtp->did, &msg);
    if (!ret && msg) {
        eXosip_call_send_ack(mSipCtx, evtp->did, msg);
    } else {
        LOGE("eXosip_call_send_ack error=%d", ret);
    }

    // 设备接受了 INVITE，记录 cid/did
    LOGI("INVITE ACK sent, cid=%d did=%d", evtp->cid, evtp->did);
}

// ======================== 端口分配 ========================

int SipServer::allocRtpPort() {
    // RTP 端口必须为偶数，RTCP = RTP + 1
    int port = mNextRtpPort.fetch_add(2);
    return port;
}

void SipServer::releaseRtpPort(int port) {
    // 当前简单实现不做端口回收
    (void)port;
}

void SipServer::stopRtpReceiver(const std::string &device) {
    std::lock_guard<std::mutex> lock(mCallMutex);
    auto it = mCallMap.find(device);
    if (it != mCallMap.end()) {
        if (it->second.receiver) {
            it->second.receiver->stop();
            delete it->second.receiver;
            it->second.receiver = nullptr;
        }
        releaseRtpPort(it->second.rtpPort);
        mCallMap.erase(it);
        LOGI("RTP receiver stopped for device=%s", device.c_str());
    }
}

// ======================== INVITE / BYE ========================

int SipServer::request_invite(const std::string &device, const std::string &sdpPort, const std::string &sdpRtcpPort) {
    Client *client = getClientByDevice(device.c_str());
    if (!client) {
        LOGE("device %s not registered", device.c_str());
        return -1;
    }

    LOGI("INVITE device=%s", device.c_str());

    char session_exp[1024] = { 0 };
    osip_message_t *msg = nullptr;
    char from[1024] = {0};
    char to[1024] = {0};
    char sdp[2048] = {0};

    snprintf(from, sizeof(from), "sip:%s@%s:%d", mInfo->getSipId(), mInfo->getIp().c_str(), mInfo->getPort());
    snprintf(to, sizeof(to), "sip:%s@%s:%d", device.c_str(), client->getIp().c_str(), client->getPort());
    snprintf(sdp, sizeof(sdp),
             "v=0\r\n"
             "o=%s 0 0 IN IP4 %s\r\n"
             "s=Play\r\n"
             "c=IN IP4 %s\r\n"
             "t=0 0\r\n"
             "m=video %s RTP/AVP 96 98 97\r\n"
             "a=rtcp:%s IN IP4 %s\r\n"
             "a=rtcp-mux\r\n"
             "a=recvonly\r\n"
             "a=rtpmap:96 PS/90000\r\n"
             "a=rtpmap:98 H264/90000\r\n"
             "a=rtpmap:97 MPEG4/90000\r\n"
             "a=fmtp:96 profile-level-id=42001f;packetization-mode=1\r\n"
             "a=rtcp-fb:* nack pli\r\n"
             "a=rtcp-fb:* ccm fir\r\n"
             "y=0100000001\r\n"
             "f=v/0/0/0/0/0a/0/0/0\r\n",
             mInfo->getSipId(), mInfo->getIp().c_str(), mInfo->getIp().c_str(),
             sdpPort.c_str(), sdpRtcpPort.c_str(), mInfo->getIp().c_str());

    int ret = eXosip_call_build_initial_invite(mSipCtx, &msg, to, from, nullptr, nullptr);
    if (ret) {
        LOGE("eXosip_call_build_initial_invite error: %s %s ret:%d", from, to, ret);
        return -1;
    }

    osip_message_set_body(msg, sdp, strlen(sdp));
    osip_message_set_content_type(msg, "application/sdp");
    snprintf(session_exp, sizeof(session_exp)-1, "%i;refresher=uac", mInfo->getTimeout());
    osip_message_set_header(msg, "Session-Expires", session_exp);
    osip_message_set_supported(msg, "timer");

    // 打印完整 INVITE 消息体
    {
        char *msgStr = nullptr;
        size_t msgLen = 0;
        osip_message_to_str(msg, &msgStr, &msgLen);
        if (msgStr) {
            LOGI("INVITE full message:\n%s", msgStr);
            osip_free(msgStr);
        }
    }

    int call_id = eXosip_call_send_initial_invite(mSipCtx, msg);

    if (call_id > 0) {
        LOGI("eXosip_call_send_initial_invite success: call_id=%d", call_id);
        return 0;
    } else {
        LOGE("eXosip_call_send_initial_invite error: call_id=%d", call_id);
        return -1;
    }
}

int SipServer::request_bye(const std::string &device) {
    std::lock_guard<std::mutex> lock(mCallMutex);
    auto it = mCallMap.find(device);
    if (it == mCallMap.end()) {
        LOGE("no active call for device=%s", device.c_str());
        return -1;
    }

    int cid = it->second.cid;
    int did = it->second.did;

    eXosip_lock(mSipCtx);
    int ret = eXosip_call_terminate(mSipCtx, cid, did);
    eXosip_unlock(mSipCtx);

    if (it->second.receiver) {
        it->second.receiver->stop();
        delete it->second.receiver;
    }
    releaseRtpPort(it->second.rtpPort);
    mCallMap.erase(it);

    LOGI("BYE sent to device=%s, ret=%d", device.c_str(), ret);
    return ret;
}

// ======================== HTTP API ========================

int SipServer::httpInvite(const std::string &device) {
    Client *client = getClientByDevice(device.c_str());
    if (!client) {
        LOGE("httpInvite: device %s not registered", device.c_str());
        return -1;
    }

    // 检查是否已有活跃的 call
    {
        std::lock_guard<std::mutex> lock(mCallMutex);
        if (mCallMap.find(device) != mCallMap.end()) {
            LOGE("httpInvite: device %s already has active call", device.c_str());
            return -1;
        }
    }

    // 分配 RTP/RTCP 端口
    int rtpPort = allocRtpPort();
    int rtcpPort = rtpPort + 1;

    // 创建 RTP receiver，绑定 0.0.0.0 接收所有网卡流量
    RtpReceiver *receiver = new RtpReceiver("0.0.0.0", rtpPort, rtcpPort, device);
    if (!receiver->start()) {
        LOGE("httpInvite: RtpReceiver start failed for device=%s rtp=%d rtcp=%d",
             device.c_str(), rtpPort, rtcpPort);
        delete receiver;
        releaseRtpPort(rtpPort);
        return -1;
    }

    // SDP 中填 RTP/RTCP 端口
    char sdpPort[16];
    char sdpRtcpPort[16];
    snprintf(sdpPort, sizeof(sdpPort), "%d", rtpPort);
    snprintf(sdpRtcpPort, sizeof(sdpRtcpPort), "%d", rtcpPort);

    int ret = request_invite(device, sdpPort, sdpRtcpPort);
    if (ret != 0) {
        receiver->stop();
        delete receiver;
        releaseRtpPort(rtpPort);
        return -1;
    }

    // 记录 call session
    {
        std::lock_guard<std::mutex> lock(mCallMutex);
        CallSession session;
        session.rtpPort = rtpPort;
        session.rtcpPort = rtcpPort;
        session.receiver = receiver;
        // cid/did 在 EXOSIP_CALL_ANSWERED 时更新
        mCallMap[device] = session;
    }

    LOGI("httpInvite: device=%s rtp=%d rtcp=%d", device.c_str(), rtpPort, rtcpPort);
    return 0;
}

int SipServer::httpBye(const std::string &device) {
    return request_bye(device);
}

std::string SipServer::httpListDevices() {
    std::string result = "{\"code\":0,\"devices\":[";
    bool first = true;
    for (auto &kv : mClientMap) {
        if (!first) result += ",";
        char entry[256];
        snprintf(entry, sizeof(entry), "{\"device\":\"%s\",\"ip\":\"%s\",\"port\":%d}",
                 kv.second->getDevice().c_str(), kv.second->getIp().c_str(), kv.second->getPort());
        result += entry;
        first = false;
    }
    result += "],\"calls\":[";
    first = true;
    std::lock_guard<std::mutex> lock(mCallMutex);
    for (auto &kv : mCallMap) {
        if (!first) result += ",";
        char entry[256];
        snprintf(entry, sizeof(entry), "{\"device\":\"%s\",\"rtpPort\":%d,\"rtcpPort\":%d}",
                 kv.first.c_str(), kv.second.rtpPort, kv.second.rtcpPort);
        result += entry;
        first = false;
    }
    result += "]}";
    return result;
}

// ======================== Record Info ========================

int SipServer::request_record_info(const char *device, const char *userIp, int userPort,
                                   const char *startTime, const char *endTime) {
    if (device == nullptr || userIp == nullptr || startTime == nullptr || endTime == nullptr) {
        LOGE("request_record_info invalid args");
        return -1;
    }

    osip_message_t *msg = nullptr;
    char from[1024] = {0};
    char to[1024] = {0};
    char xml[2048] = {0};

    snprintf(from, sizeof(from), "sip:%s@%s:%d", mInfo->getSipId(), mInfo->getIp().c_str(), mInfo->getPort());
    snprintf(to, sizeof(to), "sip:%s@%s:%d", device, userIp, userPort);
    snprintf(xml, sizeof(xml),
             "<?xml version=\"1.0\"?>\r\n"
             "<Query>\r\n"
             "<CmdType>RecordInfo</CmdType>\r\n"
             "<SN>%d</SN>\r\n"
             "<DeviceID>%s</DeviceID>\r\n"
             "<StartTime>%s</StartTime>\r\n"
             "<EndTime>%s</EndTime>\r\n"
             "<Secrecy>0</Secrecy>\r\n"
             "<Type>all</Type>\r\n"
             "</Query>\r\n",
             this->next_sn(), device, startTime, endTime);

    int ret = eXosip_message_build_request(mSipCtx, &msg, "MESSAGE", to, from, nullptr);
    if (ret != 0 || msg == nullptr) {
        LOGE("eXosip_message_build_request RecordInfo error: ret=%d", ret);
        return -1;
    }

    osip_message_set_body(msg, xml, strlen(xml));
    osip_message_set_content_type(msg, "Application/MANSCDP+xml");

    eXosip_lock(mSipCtx);
    ret = eXosip_message_send_request(mSipCtx, msg);
    eXosip_unlock(mSipCtx);

    if (ret == 0) {
        LOGI("RecordInfo query sent: device=%s, start=%s, end=%s", device, startTime, endTime);
    } else {
        LOGE("RecordInfo query send failed: device=%s, ret=%d", device, ret);
    }

    return ret;
}

void SipServer::enqueue_record_query(const char *device, const char *userIp, int userPort) {
    if (device == nullptr || userIp == nullptr) {
        return;
    }

    for (auto &query : mPendingRecordQueries) {
        if (query.device == device) {
            query.ip = userIp;
            query.port = userPort;
            query.executeAt = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
            return;
        }
    }

    PendingRecordQuery query;
    query.device = device;
    query.ip = userIp;
    query.port = userPort;
    query.executeAt = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
    mPendingRecordQueries.push_back(query);
}

void SipServer::process_pending_record_queries() {
    while (!mPendingRecordQueries.empty()) {
        PendingRecordQuery &query = mPendingRecordQueries.front();
        if (std::chrono::steady_clock::now() < query.executeAt) {
            break;
        }

        std::string startTime = this->build_record_query_time(true);
        std::string endTime = this->build_record_query_time(false);
        this->request_record_info(query.device.c_str(), query.ip.c_str(), query.port,
                                  startTime.c_str(), endTime.c_str());
        mPendingRecordQueries.pop_front();
    }
}

std::string SipServer::build_record_query_time(bool startOfDay) const {
    std::time_t now = std::time(nullptr);
    std::tm timeInfo;
    localtime_r(&now, &timeInfo);

    if (startOfDay) {
        timeInfo.tm_hour = 0;
        timeInfo.tm_min = 0;
        timeInfo.tm_sec = 0;
    }

    char value[32] = {0};
    std::strftime(value, sizeof(value), "%Y-%m-%dT%H:%M:%S", &timeInfo);
    return value;
}

int SipServer::next_sn() {
    return mSn.fetch_add(1);
}

int SipServer::clearClientMap(){
    // 停止所有 RTP receiver
    {
        std::lock_guard<std::mutex> lock(mCallMutex);
        for (auto &kv : mCallMap) {
            if (kv.second.receiver) {
                kv.second.receiver->stop();
                delete kv.second.receiver;
            }
        }
        mCallMap.clear();
    }

    std::map<std::string ,Client *>::iterator iter;
    for (iter=mClientMap.begin(); iter!=mClientMap.end(); iter++) {
        delete iter->second;
        iter->second = nullptr;
    }
    mClientMap.clear();

    return 0;
}

Client * SipServer::getClientByDevice(const char *device) {
    auto it = mClientMap.find(device);
    if(it == mClientMap.end()){
        return nullptr;
    }
    return it->second;
}

int SipServer::parse_xml(const char *data, const char *s_mark, bool with_s_make, const char *e_mark, bool with_e_make, char *dest) {
    if (data == nullptr || s_mark == nullptr || e_mark == nullptr || dest == nullptr) {
        return -1;
    }
    const char* satrt = strstr( data, s_mark );

    if(satrt != NULL) {
        const char* end = strstr(satrt, e_mark);

        if(end != NULL){
            int s_pos = with_s_make ? 0 : strlen(s_mark);
            int e_pos = with_e_make ? strlen(e_mark) : 0;

            strncpy( dest, satrt+s_pos, (end+e_pos) - (satrt+s_pos) );
        }
        return 0;
    }
    return -1;

}

void SipServer::dump_request(eXosip_event_t *evtp) {
    char *s;
    size_t len;
    osip_message_to_str(evtp->request, &s, &len);
    LOGI("\nprint request start\ntype=%d\n%s\nprint request end\n",evtp->type,s);
}

void SipServer::dump_response(eXosip_event_t *evtp) {
    char *s;
    size_t len;
    osip_message_to_str(evtp->response, &s, &len);
    LOGI("\nprint response start\ntype=%d\n%s\nprint response end\n",evtp->type,s);
}
