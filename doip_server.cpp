#include "doip_server.h"
#include <algorithm>
#include <string>

DoIPServer::DoIPServer(std::vector<std::string> allowedIPs)
    : session_(DiagSession::Discovery),
      udpSocket_(INVALID_SOCKET),
      tcpSocket_(INVALID_SOCKET),
      clientSocket_(INVALID_SOCKET),
      validClientIPs_(std::move(allowedIPs))
{}

DoIPServer::~DoIPServer() { Cleanup(); }

bool DoIPServer::Init()
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        LOG_VERBOSE("WSAStartup failed with error %d\n", WSAGetLastError());
        return false;
    }
    AddLocalIPs();
    return true;
}

void DoIPServer::Run()
{
    while (true)
    {
        switch (session_)
        {
        case DiagSession::Discovery:         PerformDiscovery();         break;
        case DiagSession::Discovered:        PerformTcpSetup();          break;
        case DiagSession::Connecting:        PerformRoutingActivation(); break;
        case DiagSession::ActiveDiagSession: PerformDiagnostics();       break;
        default:
            LOG_VERBOSE("Unrecognized session state, aborting\n");
            return;
        }
    }
}

void DoIPServer::AddLocalIPs()
{
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0)
    {
        LOG_VERBOSE("gethostname failed with error %d, "
                    "local IPs not added to allowed client list\n", WSAGetLastError());
        return;
    }

    addrinfo hints{};
    hints.ai_family = AF_INET;
    addrinfo* result = nullptr;

    if (getaddrinfo(hostname, nullptr, &hints, &result) != 0)
    {
        LOG_VERBOSE("getaddrinfo for hostname '%s' failed with error %d\n",
                    hostname, WSAGetLastError());
        return;
    }

    for (addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next)
    {
        char ipStr[INET_ADDRSTRLEN];
        auto* addr = reinterpret_cast<sockaddr_in*>(ptr->ai_addr);
        InetNtopA(AF_INET, &addr->sin_addr, ipStr, INET_ADDRSTRLEN);

        if (std::find(validClientIPs_.begin(), validClientIPs_.end(), ipStr)
            == validClientIPs_.end())
        {
            validClientIPs_.push_back(ipStr);
            LOG_VERBOSE("Local IP %s automatically added to allowed client list\n", ipStr);
        }
    }
    freeaddrinfo(result);

    if (std::find(validClientIPs_.begin(), validClientIPs_.end(), "127.0.0.1")
        == validClientIPs_.end())
    {
        validClientIPs_.push_back("127.0.0.1");
        LOG_VERBOSE("Loopback 127.0.0.1 automatically added to allowed client list\n");
    }
}

void DoIPServer::CloseSocket(SOCKET& s)
{
    if (s != INVALID_SOCKET)
    {
        closesocket(s);
        s = INVALID_SOCKET;
    }
}

void DoIPServer::Cleanup()
{
    CloseSocket(clientSocket_);
    CloseSocket(tcpSocket_);
    CloseSocket(udpSocket_);
    WSACleanup();
}

bool DoIPServer::IsClientAllowed(const std::string& ip) const
{
    return std::find(validClientIPs_.begin(), validClientIPs_.end(), ip)
           != validClientIPs_.end();
}

void DoIPServer::ResetToDiscovery()
{
    CloseSocket(clientSocket_);
    CloseSocket(tcpSocket_);
    discoveredClientIP_.clear();
    session_ = DiagSession::Discovery;
    LOG_VERBOSE("Session reset, restarting discovery\n");
}

void DoIPServer::PerformDiscovery()
{
    LOG_INFO("Waiting for VehicleIdent_Req on UDP port %u\n", DOIP_PORT);

    udpSocket_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket_ == INVALID_SOCKET)
    {
        LOG_VERBOSE("UDP socket creation failed with error %d\n", WSAGetLastError());
        return;
    }

    BOOL broadcastEnabled = TRUE;
    setsockopt(udpSocket_, SOL_SOCKET, SO_BROADCAST,
               reinterpret_cast<char*>(&broadcastEnabled), sizeof(broadcastEnabled));

    sockaddr_in bindAddr{};
    bindAddr.sin_family      = AF_INET;
    bindAddr.sin_port        = htons(DOIP_PORT);
    bindAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(udpSocket_, reinterpret_cast<sockaddr*>(&bindAddr), sizeof(bindAddr))
        == SOCKET_ERROR)
    {
        LOG_VERBOSE("UDP bind to port %u failed with error %d\n",
                    DOIP_PORT, WSAGetLastError());
        CloseSocket(udpSocket_);
        return;
    }

    uint8_t buffer[DOIP_HEADER_SIZE + DOIP_MAX_PAYLOAD_BYTES];
    sockaddr_in senderAddr{};
    int senderLen = sizeof(senderAddr);
    char ipStr[INET_ADDRSTRLEN];

    while (true)
    {
        const int received = recvfrom(udpSocket_,
                                      reinterpret_cast<char*>(buffer),
                                      sizeof(buffer),
                                      0,
                                      reinterpret_cast<sockaddr*>(&senderAddr),
                                      &senderLen);
        if (received < 0)
        {
            LOG_VERBOSE("UDP recvfrom failed with error %d, aborting discovery\n",
                        WSAGetLastError());
            CloseSocket(udpSocket_);
            return;
        }
        if (received == 0) continue;

        InetNtopA(AF_INET, &senderAddr.sin_addr, ipStr, INET_ADDRSTRLEN);

        const auto msg = ParseUdpDatagram(buffer, received);
        if (!msg) continue;

        if (msg->type != static_cast<uint16_t>(PayloadType::VehicleIdent_Req))
        {
            LOG_VERBOSE("Ignoring unexpected UDP payload type 0x%04X from %s, "
                        "sending Generic_DoIP_NACK\n", msg->type, ipStr);
            SendUdpNack(udpSocket_, senderAddr, GenericNackCode::UnknownPayloadType);
            continue;
        }

        if (!IsClientAllowed(ipStr))
        {
            LOG_VERBOSE("VehicleIdent_Req from %s rejected: "
                        "IP not in allowed client list\n", ipStr);
            continue;
        }

        SendVehicleIdentResponse(senderAddr);
        discoveredClientIP_ = ipStr;
        session_            = DiagSession::Discovered;
        CloseSocket(udpSocket_);
        LOG_INFO("VehicleIdent_Req accepted from %s, transitioning to TCP setup\n", ipStr);
        return;
    }
}

void DoIPServer::SendVehicleIdentResponse(const sockaddr_in& target)
{
    const auto frame = BuildVehicleIdentResponse(vehicleInfo_);
    if (sendto(udpSocket_,
               reinterpret_cast<const char*>(frame.data()),
               static_cast<int>(frame.size()),
               0,
               reinterpret_cast<const sockaddr*>(&target),
               sizeof(target))
        == SOCKET_ERROR)
    {
        LOG_VERBOSE("Sending VehicleIdent_Res failed with error %d\n", WSAGetLastError());
    }
    else
    {
        LOG_VERBOSE("VehicleIdent_Res sent\n");
    }
}

void DoIPServer::PerformTcpSetup()
{
    LOG_INFO("Listening for TCP connection from %s on port %u\n",
             discoveredClientIP_.c_str(), DOIP_PORT);

    tcpSocket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (tcpSocket_ == INVALID_SOCKET)
    {
        LOG_VERBOSE("TCP listener socket creation failed with error %d\n", WSAGetLastError());
        return;
    }

    BOOL reuseAddr = TRUE;
    setsockopt(tcpSocket_, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<char*>(&reuseAddr), sizeof(reuseAddr));

    sockaddr_in bindAddr{};
    bindAddr.sin_family      = AF_INET;
    bindAddr.sin_port        = htons(DOIP_PORT);
    bindAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(tcpSocket_, reinterpret_cast<sockaddr*>(&bindAddr), sizeof(bindAddr))
        == SOCKET_ERROR)
    {
        LOG_VERBOSE("TCP bind to port %u failed with error %d\n",
                    DOIP_PORT, WSAGetLastError());
        CloseSocket(tcpSocket_);
        return;
    }

    if (listen(tcpSocket_, 1) == SOCKET_ERROR)
    {
        LOG_VERBOSE("TCP listen on port %u failed with error %d\n",
                    DOIP_PORT, WSAGetLastError());
        CloseSocket(tcpSocket_);
        return;
    }

    sockaddr_in clientAddr{};
    int addrLen   = sizeof(clientAddr);
    clientSocket_ = accept(tcpSocket_,
                            reinterpret_cast<sockaddr*>(&clientAddr),
                            &addrLen);
    CloseSocket(tcpSocket_); // listener no longer needed once a connection is accepted

    if (clientSocket_ == INVALID_SOCKET)
    {
        LOG_VERBOSE("TCP accept failed with error %d\n", WSAGetLastError());
        return;
    }

    char ipStr[INET_ADDRSTRLEN];
    InetNtopA(AF_INET, &clientAddr.sin_addr, ipStr, INET_ADDRSTRLEN);

    if (std::string(ipStr) != discoveredClientIP_)
    {
        LOG_VERBOSE("TCP connection from %s rejected: "
                    "expected the UDP-discovered client %s\n",
                    ipStr, discoveredClientIP_.c_str());
        CloseSocket(clientSocket_);
        return;
    }

    DWORD initTimeout = TCP_INITIAL_INACTIVITY_TIMEOUT_MS;
    setsockopt(clientSocket_, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<char*>(&initTimeout), sizeof(initTimeout));

    LOG_INFO("TCP connection accepted from %s\n", ipStr);
    session_ = DiagSession::Connecting;
}

void DoIPServer::PerformRoutingActivation()
{
    LOG_INFO("Waiting for Routing_Activ_Req from %s (timeout: %u ms)\n",
             discoveredClientIP_.c_str(), TCP_INITIAL_INACTIVITY_TIMEOUT_MS);

    const auto msg = ReceiveTcpMessage(clientSocket_);
    if (!msg)
    {
        const int err = WSAGetLastError();
        if (err == WSAETIMEDOUT)
            LOG_VERBOSE("Initial inactivity timeout: no Routing_Activ_Req received "
                        "within %u ms\n", TCP_INITIAL_INACTIVITY_TIMEOUT_MS);
        else
            LOG_VERBOSE("Connection from %s lost while waiting for Routing_Activ_Req "
                        "(error %d)\n", discoveredClientIP_.c_str(), err);
        ResetToDiscovery();
        return;
    }

    if (msg->type != static_cast<uint16_t>(PayloadType::Routing_Activ_Req))
    {
        LOG_VERBOSE("Expected Routing_Activ_Req (0x%04X) but received type 0x%04X "
                    "from %s\n",
                    static_cast<uint16_t>(PayloadType::Routing_Activ_Req),
                    msg->type,
                    discoveredClientIP_.c_str());
        SendTcpNack(clientSocket_, GenericNackCode::UnknownPayloadType);
        ResetToDiscovery();
        return;
    }

    // SA(2) | ActivationType(1) | Reserved ISO(4) = 7 bytes minimum
    if (msg->payload.size() < 7)
    {
        LOG_VERBOSE("Routing_Activ_Req from %s has payload too short: "
                    "%zu bytes (expected >= 7)\n",
                    discoveredClientIP_.c_str(), msg->payload.size());
        SendTcpNack(clientSocket_, GenericNackCode::InvalidPayloadLength);
        ResetToDiscovery();
        return;
    }

    const uint16_t testerAddr = RoutingActivSourceAddr(*msg);
    LOG_INFO("Routing_Activ_Req from tester 0x%04X, activation type 0x%02X\n",
             testerAddr, RoutingActivType(*msg));

    const auto response = BuildRoutingActivationResponse(
        testerAddr, ENTITY_LOGICAL_ADDR, RoutingActivationCode::SuccessfullyActivated);

    if (!SendFrame(clientSocket_, response))
    {
        LOG_VERBOSE("Sending Routing_Activ_Res to %s failed with error %d\n",
                    discoveredClientIP_.c_str(), WSAGetLastError());
        ResetToDiscovery();
        return;
    }

    DWORD generalTimeout = TCP_GENERAL_INACTIVITY_TIMEOUT_MS;
    setsockopt(clientSocket_, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<char*>(&generalTimeout), sizeof(generalTimeout));

    LOG_INFO("Routing activation for tester 0x%04X successful\n", testerAddr);
    session_ = DiagSession::ActiveDiagSession;
}

void DoIPServer::PerformDiagnostics()
{
    LOG_INFO("Diagnostic session active, waiting for messages from %s\n",
             discoveredClientIP_.c_str());

    while (true)
    {
        const auto msg = ReceiveTcpMessage(clientSocket_);
        if (!msg)
        {
            const int err = WSAGetLastError();
            if (err == WSAETIMEDOUT)
                LOG_VERBOSE("General inactivity timeout: no message received within %u ms, "
                            "closing session\n", TCP_GENERAL_INACTIVITY_TIMEOUT_MS);
            else
                LOG_VERBOSE("Connection from %s lost during diagnostics (error %d)\n",
                            discoveredClientIP_.c_str(), err);
            ResetToDiscovery();
            return;
        }

        switch (static_cast<PayloadType>(msg->type))
        {
        case PayloadType::DIAG_Msg:
            if (msg->payload.size() >= 4)
            {
                if (LogLevel::INFO >= g_logLevel)
                {
                    printf("DIAG_Msg from SA=0x%04X to TA=0x%04X, UDS bytes:",
                           DiagSourceAddr(*msg), DiagTargetAddr(*msg));
                    for (size_t i = 4; i < msg->payload.size(); ++i)
                        printf(" %02X", msg->payload[i]);
                    printf("\n");
                }
                SendDiagAck(DiagSourceAddr(*msg));
            }
            else
            {
                LOG_VERBOSE("DIAG_Msg from %s too short for address fields: "
                            "%zu bytes\n", discoveredClientIP_.c_str(), msg->payload.size());
                SendTcpNack(clientSocket_, GenericNackCode::InvalidPayloadLength);
            }
            break;

        case PayloadType::Alive_Check_Req:
            LOG_ALL("Alive_Check_Req received from %s\n", discoveredClientIP_.c_str());
            if (!SendFrame(clientSocket_, BuildAliveCheckResponse(ENTITY_LOGICAL_ADDR)))
                LOG_VERBOSE("Sending Alive_Check_Res to %s failed with error %d\n",
                            discoveredClientIP_.c_str(), WSAGetLastError());
            else
                LOG_ALL("Alive_Check_Res sent to %s\n", discoveredClientIP_.c_str());
            break;

        case PayloadType::Generic_DoIP_NACK:
            LOG_VERBOSE("Generic_DoIP_NACK received from %s with code 0x%02X\n",
                        discoveredClientIP_.c_str(),
                        msg->payload.empty() ? 0xFF : msg->payload[0]);
            break;

        default:
            LOG_VERBOSE("Unhandled payload type 0x%04X received from %s, "
                        "sending Generic_DoIP_NACK\n",
                        msg->type, discoveredClientIP_.c_str());
            SendTcpNack(clientSocket_, GenericNackCode::UnknownPayloadType);
            break;
        }
    }
}

void DoIPServer::SendDiagAck(uint16_t testerAddr)
{
    const auto frame = BuildDiagAck(ENTITY_LOGICAL_ADDR, testerAddr, 0x00);
    if (!SendFrame(clientSocket_, frame))
        LOG_VERBOSE("Sending DIAG_Msg_ACK to tester 0x%04X failed with error %d\n",
                    testerAddr, WSAGetLastError());
    else
        LOG_INFO("DIAG_Msg_ACK sent to tester 0x%04X\n", testerAddr);
}

int main()
{
    DoIPServer server({"192.168.0.10", "192.168.0.11"});
    if (!server.Init()) return 1;
    server.Run();
    return 0;
}
