//
// RtpReceiver.cpp
// UDP receiver for RTP and RTCP packets with parsing and logging
// Periodically sends RTCP Receiver Report back to the sender
//

#include "RtpReceiver.h"
#include "Utils/Log.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>

RtpReceiver::RtpReceiver(const std::string &bindIp, int rtpPort, int rtcpPort, const std::string &deviceId)
    : mBindIp(bindIp), mRtpPort(rtpPort), mRtcpPort(rtcpPort), mDeviceId(deviceId) {
    mStartTime = std::chrono::steady_clock::now();
}

RtpReceiver::~RtpReceiver() {
    stop();
}

void RtpReceiver::setSenderAddr(const std::string &ip, int rtcpPort) {
    mSenderIp = ip;
    mSenderRtcpPort = rtcpPort;
    memset(&mSenderAddr, 0, sizeof(mSenderAddr));
    mSenderAddr.sin_family = AF_INET;
    mSenderAddr.sin_port = htons(rtcpPort);
    inet_pton(AF_INET, ip.c_str(), &mSenderAddr.sin_addr);
    mSenderAddrValid = true;
    LOGI("[RtpReceiver] RTCP RR target: %s:%d for device=%s", ip.c_str(), rtcpPort, mDeviceId.c_str());
}

bool RtpReceiver::start() {
    // --- RTP socket ---
    mRtpSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (mRtpSock < 0) {
        LOGE("RTP socket create failed: %s", strerror(errno));
        return false;
    }

    int reuse = 1;
    setsockopt(mRtpSock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(mRtpPort);
    if (mBindIp.empty() || mBindIp == "0.0.0.0") {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        inet_pton(AF_INET, mBindIp.c_str(), &addr.sin_addr);
    }

    if (bind(mRtpSock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOGE("RTP bind %s:%d failed: %s", mBindIp.c_str(), mRtpPort, strerror(errno));
        close(mRtpSock);
        mRtpSock = -1;
        return false;
    }

    // --- RTCP socket ---
    mRtcpSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (mRtcpSock < 0) {
        LOGE("RTCP socket create failed: %s", strerror(errno));
        close(mRtpSock);
        mRtpSock = -1;
        return false;
    }

    setsockopt(mRtcpSock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in rtcpAddr{};
    rtcpAddr.sin_family = AF_INET;
    rtcpAddr.sin_port = htons(mRtcpPort);
    if (mBindIp.empty() || mBindIp == "0.0.0.0") {
        rtcpAddr.sin_addr.s_addr = INADDR_ANY;
    } else {
        inet_pton(AF_INET, mBindIp.c_str(), &rtcpAddr.sin_addr);
    }

    if (bind(mRtcpSock, (struct sockaddr *)&rtcpAddr, sizeof(rtcpAddr)) < 0) {
        LOGE("RTCP bind %s:%d failed: %s", mBindIp.c_str(), mRtcpPort, strerror(errno));
        close(mRtpSock);
        close(mRtcpSock);
        mRtpSock = -1;
        mRtcpSock = -1;
        return false;
    }

    mRunning = true;
    mRtpThread = std::thread(&RtpReceiver::rtpLoop, this);
    mRtcpThread = std::thread(&RtpReceiver::rtcpLoop, this);
    mRrThread = std::thread(&RtpReceiver::rrLoop, this);

    LOGI("[RtpReceiver] Started for device=%s, RTP=%d, RTCP=%d", mDeviceId.c_str(), mRtpPort, mRtcpPort);
    return true;
}

void RtpReceiver::stop() {
    if (!mRunning) return;
    mRunning = false;

    if (mRtpSock >= 0) {
        shutdown(mRtpSock, SHUT_RDWR);
        close(mRtpSock);
        mRtpSock = -1;
    }
    if (mRtcpSock >= 0) {
        shutdown(mRtcpSock, SHUT_RDWR);
        close(mRtcpSock);
        mRtcpSock = -1;
    }

    if (mRtpThread.joinable()) mRtpThread.join();
    if (mRtcpThread.joinable()) mRtcpThread.join();
    if (mRrThread.joinable()) mRrThread.join();

    LOGI("[RtpReceiver] Stopped for device=%s, RTP pkts=%lu bytes=%lu, RTCP pkts=%lu",
         mDeviceId.c_str(),
         (unsigned long)mRtpPktCount.load(),
         (unsigned long)mRtpByteCount.load(),
         (unsigned long)mRtcpPktCount.load());
}

void RtpReceiver::rtpLoop() {
    uint8_t *buf = new uint8_t[RECV_BUF_SIZE];
    while (mRunning) {
        struct sockaddr_in srcAddr{};
        socklen_t srcLen = sizeof(srcAddr);
        ssize_t n = recvfrom(mRtpSock, buf, RECV_BUF_SIZE, 0, (struct sockaddr *)&srcAddr, &srcLen);
        if (n <= 0) {
            if (!mRunning) break;
            continue;
        }

        // 从第一个 RTP 包自动推算对端 RTCP 地址（RTP 端口 + 1）
        if (!mSenderAddrValid && srcAddr.sin_family == AF_INET) {
            char srcIp[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &srcAddr.sin_addr, srcIp, sizeof(srcIp));
            int srcPort = ntohs(srcAddr.sin_port);
            // RTCP 端口 = RTP 端口 + 1（约定）
            setSenderAddr(srcIp, srcPort + 1);
        }

        mRtpPktCount++;
        mRtpByteCount += n;
        parseRtp(buf, (size_t)n);
    }
    delete[] buf;
}

void RtpReceiver::rtcpLoop() {
    uint8_t *buf = new uint8_t[RECV_BUF_SIZE];
    while (mRunning) {
        ssize_t n = recv(mRtcpSock, buf, RECV_BUF_SIZE, 0);
        if (n <= 0) {
            if (!mRunning) break;
            continue;
        }
        mRtcpPktCount++;
        parseRtcp(buf, (size_t)n);
    }
    delete[] buf;
}

void RtpReceiver::rrLoop() {
    while (mRunning) {
        // 等待 5 秒，每 100ms 检查一次 mRunning 以便快速退出
        for (int i = 0; i < 50 && mRunning; i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (!mRunning) break;
        sendRtcpRR();
    }
}

// ======================== RTCP RR 发送 ========================

void RtpReceiver::sendRtcpRR() {
    if (!mSenderAddrValid || mRtcpSock < 0) return;

    uint32_t ssrc = mSsrc.load();
    if (ssrc == 0) return; // 还没收到 RTP，不知道对端 SSRC

    uint8_t buf[128];
    size_t len = 0;
    buildReceiverReport(buf, len);

    ssize_t sent = sendto(mRtcpSock, buf, len, 0,
                           (struct sockaddr *)&mSenderAddr, sizeof(mSenderAddr));
    if (sent < 0) {
        LOGE("[RTCP] send RR to %s:%d failed: %s",
             mSenderIp.c_str(), mSenderRtcpPort, strerror(errno));
    }
}

void RtpReceiver::buildReceiverReport(uint8_t *buf, size_t &len) {
    // RFC 3550 Receiver Report
    // Compound: SR header (empty sender) + RR block
    //
    // 我们是纯接收端，不发 RTP，所以发的是 RR（PT=201）
    // 如果我们没有发送过任何 RTP，第一个包就是 RR
    // 格式:
    //   RR header (4 bytes) + SSRC of sender (4 bytes) + 1 report block (24 bytes) = 32 bytes

    uint32_t ssrc = mSsrc.load();
    uint16_t lastSeq = mLastSeq.load();
    uint64_t pktCount = mRtpPktCount.load();

    // 计算丢包率（简化）
    uint32_t extSeq = lastSeq; // 扩展序号（简化处理，不考虑回绕）
    uint32_t expected = extSeq;
    uint32_t cumLost = 0;
    uint8_t fracLost = 0;
    if (expected > 0 && pktCount < expected) {
        cumLost = (uint32_t)(expected - pktCount);
        fracLost = (uint8_t)((cumLost * 256) / (expected > 0 ? expected : 1));
        if (fracLost > 255) fracLost = 255;
    }

    // 计算 jitter（简化：设为 0）
    uint32_t jitter = 0;

    // 计算 LSR 和 DLSR
    // 我们目前不跟踪对端 NTP 时间戳，填 0
    uint32_t lsr = 0;
    uint32_t dlsr = 0;

    size_t pos = 0;

    // RR header
    // V=2, P=0, RC=1 (1 report block), PT=201(RR)
    buf[pos++] = 0x80 | (1 & 0x1F); // V=2, P=0, RC=1
    buf[pos++] = 201;                // PT = RR
    // length = (总字节数/4) - 1 = (32/4)-1 = 7
    buf[pos++] = 0x00;
    buf[pos++] = 0x07;

    // SSRC of packet sender（我们自己生成的 SSRC，用端口号做简单标识）
    uint32_t mySsrc = (uint32_t)(mRtpPort);
    buf[pos++] = (mySsrc >> 24) & 0xFF;
    buf[pos++] = (mySsrc >> 16) & 0xFF;
    buf[pos++] = (mySsrc >> 8) & 0xFF;
    buf[pos++] = mySsrc & 0xFF;

    // Report block 1
    // SSRC of source
    buf[pos++] = (ssrc >> 24) & 0xFF;
    buf[pos++] = (ssrc >> 16) & 0xFF;
    buf[pos++] = (ssrc >> 8) & 0xFF;
    buf[pos++] = ssrc & 0xFF;

    // Fraction lost + Cumulative lost
    buf[pos++] = fracLost;
    buf[pos++] = (cumLost >> 16) & 0xFF;
    buf[pos++] = (cumLost >> 8) & 0xFF;
    buf[pos++] = cumLost & 0xFF;

    // Extended highest sequence number
    buf[pos++] = (extSeq >> 24) & 0xFF;
    buf[pos++] = (extSeq >> 16) & 0xFF;
    buf[pos++] = (extSeq >> 8) & 0xFF;
    buf[pos++] = extSeq & 0xFF;

    // Interarrival jitter
    buf[pos++] = (jitter >> 24) & 0xFF;
    buf[pos++] = (jitter >> 16) & 0xFF;
    buf[pos++] = (jitter >> 8) & 0xFF;
    buf[pos++] = jitter & 0xFF;

    // Last SR (LSR)
    buf[pos++] = (lsr >> 24) & 0xFF;
    buf[pos++] = (lsr >> 16) & 0xFF;
    buf[pos++] = (lsr >> 8) & 0xFF;
    buf[pos++] = lsr & 0xFF;

    // Delay since last SR (DLSR)
    buf[pos++] = (dlsr >> 24) & 0xFF;
    buf[pos++] = (dlsr >> 16) & 0xFF;
    buf[pos++] = (dlsr >> 8) & 0xFF;
    buf[pos++] = dlsr & 0xFF;

    len = pos;

    LOGI("[RTCP] RR sent: device=%s to=%s:%d ssrc=0x%08X extSeq=%u cumLost=%u fracLost=%u #pkts=%lu",
         mDeviceId.c_str(), mSenderIp.c_str(), mSenderRtcpPort,
         ssrc, extSeq, cumLost, fracLost, (unsigned long)pktCount);
}

// ======================== RTP 解析 ========================

void RtpReceiver::parseRtp(const uint8_t *data, size_t len) {
    if (len < 12) {
        LOGE("[RTP] Packet too short: %zu bytes", len);
        return;
    }

    // RFC 3550 RTP header
    uint8_t byte0 = data[0];
    int version   = (byte0 >> 6) & 0x03;
    bool padding  = (byte0 >> 5) & 0x01;
    bool extension = (byte0 >> 4) & 0x01;
    int csrcCount = byte0 & 0x0F;

    uint8_t byte1 = data[1];
    bool marker   = (byte1 >> 7) & 0x01;
    int pt        = byte1 & 0x7F;

    uint16_t seq  = (data[2] << 8) | data[3];
    uint32_t ts   = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    uint32_t ssrc = (data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11];

    if (mSsrc == 0) {
        mSsrc = ssrc;
    }

    size_t headerLen = 12 + csrcCount * 4;

    // 每100个包或关键帧包(marker=1)输出一次汇总日志，避免日志刷屏
    if (marker || mRtpPktCount % 100 == 1) {
        LOGI("[RTP] device=%s V=%d P=%d X=%d CC=%d M=%d PT=%d seq=%u ts=%u ssrc=0x%08X len=%zu hdr=%zu payload=%zu #pkts=%lu",
             mDeviceId.c_str(), version, padding, extension, csrcCount,
             marker, pt, seq, ts, ssrc, len, headerLen, len - headerLen,
             (unsigned long)mRtpPktCount.load());
    }

    // 检测丢包
    if (mLastSeq != 0) {
        uint16_t expected = mLastSeq + 1;
        if (seq != expected && !(mLastSeq > 60000 && seq < 5000)) {
            // 允许 seq 回绕
            int gap = (int)seq - (int)expected;
            if (gap < 0) gap = (int)(seq + 65536) - (int)expected;
            if (gap > 0 && gap < 1000) {
                LOGE("[RTP] device=%s SEQ gap: expected=%u got=%u gap=%d", mDeviceId.c_str(), expected, seq, gap);
            }
        }
    }
    mLastSeq = seq;
    mLastTs = ts;
}

// ======================== RTCP 解析 ========================

void RtpReceiver::parseRtcp(const uint8_t *data, size_t len) {
    if (len < 4) {
        LOGE("[RTCP] Packet too short: %zu bytes", len);
        return;
    }

    // RTCP 可能包含 compound packet，遍历解析
    size_t offset = 0;
    while (offset + 4 <= len) {
        uint8_t byte0 = data[offset];
        int version   = (byte0 >> 6) & 0x03;
        bool padding  = (byte0 >> 5) & 0x01;
        int rc        = (byte0 >> 0) & 0x1F;

        uint8_t byte1 = data[offset + 1];
        int pt        = byte1 & 0xFF;

        uint16_t length16 = (data[offset + 2] << 8) | data[offset + 3];
        size_t blockLen   = (size_t)(length16 + 1) * 4; // length in 32-bit words minus 1

        const char *ptName = "Unknown";
        switch (pt) {
            case 200: ptName = "SR";   break;
            case 201: ptName = "RR";   break;
            case 202: ptName = "SDES"; break;
            case 203: ptName = "BYE";  break;
            case 204: ptName = "APP";  break;
            case 205: ptName = "RTPFB"; break;
            case 206: ptName = "PSFB";  break;
            case 207: ptName = "XR";   break;
            default:  break;
        }

        LOGI("[RTCP] device=%s V=%d P=%d RC/SC=%d PT=%d(%s) length=%u blockLen=%zu total=%zu #pkts=%lu",
             mDeviceId.c_str(), version, padding, rc, pt, ptName, (unsigned)length16, blockLen, len,
             (unsigned long)mRtcpPktCount.load());

        // 解析 SR 的 sender info
        if (pt == 200 && blockLen >= 28 && offset + 28 <= len) {
            uint32_t srSsrc = (data[offset+4]<<24)|(data[offset+5]<<16)|(data[offset+6]<<8)|data[offset+7];
            uint32_t ntpMsw = (data[offset+8]<<24)|(data[offset+9]<<16)|(data[offset+10]<<8)|data[offset+11];
            uint32_t ntpLsw = (data[offset+12]<<24)|(data[offset+13]<<16)|(data[offset+14]<<8)|data[offset+15];
            uint32_t rtpTs  = (data[offset+16]<<24)|(data[offset+17]<<16)|(data[offset+18]<<8)|data[offset+19];
            uint32_t pktCnt = (data[offset+20]<<24)|(data[offset+21]<<16)|(data[offset+22]<<8)|data[offset+23];
            uint32_t octCnt = (data[offset+24]<<24)|(data[offset+25]<<16)|(data[offset+26]<<8)|data[offset+27];
            LOGI("[RTCP/SR] ssrc=0x%08X ntp=%u.%u rtpTs=%u pktCnt=%u octCnt=%u",
                 srSsrc, ntpMsw, ntpLsw, rtpTs, pktCnt, octCnt);
        }

        // 解析 RR
        if (pt == 201 && blockLen >= 8 && offset + 8 <= len) {
            uint32_t rrSsrc = (data[offset+4]<<24)|(data[offset+5]<<16)|(data[offset+6]<<8)|data[offset+7];
            LOGI("[RTCP/RR] ssrc=0x%08X", rrSsrc);
            // report blocks
            for (int i = 0; i < rc && (offset + 8 + (size_t)(i+1)*24) <= len; i++) {
                size_t boff = offset + 8 + i * 24;
                uint32_t blkSsrc = (data[boff]<<24)|(data[boff+1]<<16)|(data[boff+2]<<8)|data[boff+3];
                uint8_t  fracLost = data[boff+4];
                uint32_t cumLost  = (data[boff+5]<<16)|(data[boff+6]<<8)|data[boff+7];
                uint32_t extSeq   = (data[boff+8]<<24)|(data[boff+9]<<16)|(data[boff+10]<<8)|data[boff+11];
                uint32_t jitter   = (data[boff+12]<<24)|(data[boff+13]<<16)|(data[boff+14]<<8)|data[boff+15];
                LOGI("[RTCP/RR/Block] ssrc=0x%08X fracLost=%u cumLost=%u extSeq=%u jitter=%u",
                     blkSsrc, fracLost, cumLost, extSeq, jitter);
            }
        }

        // 解析 BYE
        if (pt == 203) {
            LOGI("[RTCP/BYE] device=%s rc=%d", mDeviceId.c_str(), rc);
        }

        if (blockLen == 0) break; // 防止死循环
        offset += blockLen;
    }
}
