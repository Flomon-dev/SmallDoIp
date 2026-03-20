#pragma once
#include "doip_common.h"
#include <chrono>
#include <string>
#include <vector>

class DoIPClient
{
public:
    DoIPClient();
    ~DoIPClient();

    bool Init();

    // Runs the full session state machine. Automatically rediscovers after
    // every session end or connection loss. Returns only on unrecoverable error.
    void Run();

private:
    void CloseSocket(SOCKET& s);
    void Cleanup();
    void ResetToDiscovery();

    void PerformDiscovery();
    void PerformTcpConnect();
    void PerformRoutingActivation();
    void PerformDiagnostics();

    void SendDiagnosticMessage(const std::vector<uint8_t>& udsBytes);
    void SendAliveCheck();
    void HandleDiagResponse(const DoIPMessage& msg);

    // Parses a space-separated hex string (e.g. "10 01") into bytes.
    // Returns an empty vector if any token is malformed or out of byte range.
    static std::vector<uint8_t> ParseHexBytes(const std::string& input);

    DiagSession session_;
    SOCKET      udpSocket_;
    SOCKET      tcpSocket_;
    std::string serverIP_;

    std::chrono::steady_clock::time_point lastAliveCheck_;
};
