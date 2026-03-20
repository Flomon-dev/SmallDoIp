#pragma once
#include "doip_common.h"
#include <string>
#include <vector>

class DoIPServer
{
public:
    explicit DoIPServer(std::vector<std::string> allowedIPs);
    ~DoIPServer();

    bool Init();
    void Run();

private:
    void AddLocalIPs();
    void CloseSocket(SOCKET& s);
    void Cleanup();
    bool IsClientAllowed(const std::string& ip) const;
    void ResetToDiscovery();

    void PerformDiscovery();
    void SendVehicleIdentResponse(const sockaddr_in& target);
    void PerformTcpSetup();
    void PerformRoutingActivation();
    void PerformDiagnostics();

    void SendDiagAck(uint16_t testerAddr);

    DiagSession              session_;
    SOCKET                   udpSocket_;
    SOCKET                   tcpSocket_;
    SOCKET                   clientSocket_;
    VehicleInfo              vehicleInfo_;
    std::string              discoveredClientIP_;
    std::vector<std::string> validClientIPs_;
};
