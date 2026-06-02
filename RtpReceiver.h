//
// RtpReceiver.h
// UDP receiver for RTP and RTCP packets with parsing and logging
// Periodically sends RTCP Receiver Report back to the sender
//

#ifndef BXC_SIPSERVER_RTPRECEIVER_H
#define BXC_SIPSERVER_RTPRECEIVER_H

#include <string>
#include <atomic>
#include <thread>
#include <cstdint>
#include <chrono>
#include <netinet/in.h>

class RtpReceiver {
public:
    RtpReceiver(const std::string &bindIp, int rtpPort, int rtcpPort, const std::string &deviceId);
    ~RtpReceiver();

    void setSenderAddr(const std::string &ip, int rtcpPort);
    bool start();
    void stop();

    int getRtpPort() const { return mRtpPort; }
    int getRtcpPort() const { return mRtcpPort; }
    const std::string &getDeviceId() const { return mDeviceId; }
    bool isRunning() const { return mRunning; }

private:
    void rtpLoop();
    void rtcpLoop();
    void rrLoop();
    void parseRtp(const uint8_t *data, size_t len);
    void parseRtcp(const uint8_t *data, size_t len);
    void sendRtcpRR();
    void buildReceiverReport(uint8_t *buf, size_t &len);

    std::string mBindIp;
    int mRtpPort;
    int mRtcpPort;
    std::string mDeviceId;

    int mRtpSock{-1};
    int mRtcpSock{-1};

    std::atomic<bool> mRunning{false};
    std::thread mRtpThread;
    std::thread mRtcpThread;
    std::thread mRrThread;

    // 设备端 RTCP 地址（用于回送 RR）
    std::string mSenderIp;
    int mSenderRtcpPort{0};
    struct sockaddr_in mSenderAddr{};
    bool mSenderAddrValid{false};

    // RTP stats
    std::atomic<uint64_t> mRtpPktCount{0};
    std::atomic<uint64_t> mRtpByteCount{0};
    std::atomic<uint16_t> mLastSeq{0};
    std::atomic<uint32_t> mLastTs{0};
    std::atomic<uint32_t> mSsrc{0};
    std::chrono::steady_clock::time_point mStartTime;

    // RTCP stats
    std::atomic<uint64_t> mRtcpPktCount{0};

    static constexpr size_t RECV_BUF_SIZE = 65536;
    static constexpr int RR_INTERVAL_SEC = 5; // 每5秒发一次 RR
};

#endif // BXC_SIPSERVER_RTPRECEIVER_H
