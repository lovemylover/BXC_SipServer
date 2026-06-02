//
// Created bxc on 2022/11/25.
//

#include "SipServer.h"
#include "HttpServer.h"
#include "Utils/Log.h"

int main(int argc, char *argv[]) {
    LOGI("");

    ServerInfo info(
            "BXC_SipServer",
            "1234567890123456",
            "0.0.0.0",   // SIP IP（自动检测本机IP）
            15060,       // SIP port
            10000,       // RTP port base
            9090,        // HTTP port
            "34020000002000000001",
            "3402000000",
            "123456789",
            1800,
            3600);

    SipServer sipServer(&info);

    HttpServer httpServer("0.0.0.0", info.getHttpPort());
    httpServer.setSipServer(&sipServer);

    if (!httpServer.start()) {
        LOGE("HTTP server start failed");
        return -1;
    }

    LOGI("=== BXC_SipServer started ===");
    LOGI("SIP: %s:%d", info.getIp().c_str(), info.getPort());
    LOGI("HTTP: 0.0.0.0:%d", info.getHttpPort());
    LOGI("RTP port range: %d+", info.getRtpPortBase());
    LOGI("");
    LOGI("API:");
    LOGI("  POST /invite?device=<deviceId>  - Send INVITE to device");
    LOGI("  POST /bye?device=<deviceId>     - Send BYE to device");
    LOGI("  GET  /devices                    - List registered devices");

    sipServer.loop();

    httpServer.stop();

    return 0;
}
