#include "doip_client.h"
#include <conio.h>
#include <chrono>
#include <sstream>
#include <string>

DoIPClient::DoIPClient()
    : session_(DiagSession::Discovery),
      udpSocket_(INVALID_SOCKET),
      tcpSocket_(INVALID_SOCKET),
      lastAliveCheck_(std::chrono::steady_clock::now())
{}

DoIPClient::~DoIPClient() { Cleanup(); }

bool DoIPClient::Init()
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        LOG_VERBOSE("WSAStartup failed with error %d\n", WSAGetLastError());
        return false;
    }
    return true;
}

void DoIPClient::Run()
{
    while (true)
    {
        switch (session_)
        {
        case DiagSession::Discovery:         PerformDiscovery();         break;
        case DiagSession::Discovered:        PerformTcpConnect();        break;
        case DiagSession::Connecting:        PerformRoutingActivation(); break;
        case DiagSession::ActiveDiagSession: PerformDiagnostics();       break;
        default:
            LOG_VERBOSE("Unrecognized session state, aborting\n");
            return;
        }
    }
}

void DoIPClient::CloseSocket(SOCKET& s)
{
    if (s != INVALID_SOCKET)
    {
        closesocket(s);
        s = INVALID_SOCKET;
    }
}

void DoIPClient::Cleanup()
{
    CloseSocket(tcpSocket_);
    CloseSocket(udpSocket_);
    WSACleanup();
}

void DoIPClient::ResetToDiscovery()
{
    CloseSocket(tcpSocket_);
    serverIP_.clear();
    session_ = DiagSession::Discovery;
    LOG_VERBOSE("Session reset, restarting discovery\n");
}

void DoIPClient::PerformDiscovery()
{
    if (session_ == DiagSession::ActiveDiagSession)
    {
        LOG_VERBOSE("Rediscover requested but diagnostic session is already active\n");
        return;
    }

    LOG_INFO("Sending VehicleIdent_Req broadcast on UDP port %u\n", DOIP_PORT);

    udpSocket_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket_ == INVALID_SOCKET)
    {
        LOG_VERBOSE("UDP socket creation failed with error %d\n", WSAGetLastError());
        return;
    }

    BOOL broadcastEnabled = TRUE;
    if (setsockopt(udpSocket_, SOL_SOCKET, SO_BROADCAST,
                   reinterpret_cast<char*>(&broadcastEnabled), sizeof(broadcastEnabled))
        == SOCKET_ERROR)
    {
        LOG_VERBOSE("Enabling SO_BROADCAST on UDP socket failed with error %d\n",
                    WSAGetLastError());
        CloseSocket(udpSocket_);
        return;
    }

    DWORD responseWaitTimeout = 5000;
    setsockopt(udpSocket_, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<char*>(&responseWaitTimeout), sizeof(responseWaitTimeout));

    sockaddr_in broadcastTarget{};
    broadcastTarget.sin_family      = AF_INET;
    broadcastTarget.sin_port        = htons(DOIP_PORT);
    broadcastTarget.sin_addr.s_addr = INADDR_BROADCAST;

    const auto frame = BuildVehicleIdentRequest();
    if (sendto(udpSocket_,
               reinterpret_cast<const char*>(frame.data()),
               static_cast<int>(frame.size()),
               0,
               reinterpret_cast<sockaddr*>(&broadcastTarget),
               sizeof(broadcastTarget))
        == SOCKET_ERROR)
    {
        LOG_VERBOSE("Sending VehicleIdent_Req broadcast failed with error %d\n",
                    WSAGetLastError());
        CloseSocket(udpSocket_);
        return;
    }

    LOG_INFO("Waiting for VehicleIdent_Res (timeout: %u ms)\n", responseWaitTimeout);

    uint8_t buffer[DOIP_HEADER_SIZE + DOIP_MAX_PAYLOAD_BYTES];
    sockaddr_in senderAddr{};
    int senderLen = sizeof(senderAddr);

    const int received = recvfrom(udpSocket_,
                                   reinterpret_cast<char*>(buffer),
                                   sizeof(buffer),
                                   0,
                                   reinterpret_cast<sockaddr*>(&senderAddr),
                                   &senderLen);
    if (received < 0)
    {
        const int err = WSAGetLastError();
        if (err == WSAETIMEDOUT)
            LOG_VERBOSE("VehicleIdent_Req broadcast timed out after %u ms, "
                        "no server responded\n", responseWaitTimeout);
        else
            LOG_VERBOSE("UDP recvfrom failed while waiting for VehicleIdent_Res, "
                        "error %d\n", err);
        CloseSocket(udpSocket_);
        return;
    }

    const auto msg = ParseUdpDatagram(buffer, received);
    if (!msg)
    {
        CloseSocket(udpSocket_);
        return;
    }

    if (msg->type != static_cast<uint16_t>(PayloadType::VehicleIdent_Res))
    {
        LOG_VERBOSE("Expected VehicleIdent_Res (0x%04X) but received type 0x%04X\n",
                    static_cast<uint16_t>(PayloadType::VehicleIdent_Res), msg->type);
        CloseSocket(udpSocket_);
        return;
    }

    char ipStr[INET_ADDRSTRLEN];
    InetNtopA(AF_INET, &senderAddr.sin_addr, ipStr, INET_ADDRSTRLEN);
    serverIP_ = ipStr;
    session_  = DiagSession::Discovered;

    CloseSocket(udpSocket_);
    LOG_INFO("DoIP server found at %s\n", ipStr);
}

void DoIPClient::PerformTcpConnect()
{
    LOG_INFO("Opening TCP connection to DoIP server at %s:%u\n",
             serverIP_.c_str(), DOIP_PORT);

    tcpSocket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (tcpSocket_ == INVALID_SOCKET)
    {
        LOG_VERBOSE("TCP socket creation failed with error %d\n", WSAGetLastError());
        return;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port   = htons(DOIP_PORT);
    InetPtonA(AF_INET, serverIP_.c_str(), &serverAddr.sin_addr);

    if (connect(tcpSocket_,
                reinterpret_cast<sockaddr*>(&serverAddr),
                sizeof(serverAddr))
        == SOCKET_ERROR)
    {
        LOG_VERBOSE("TCP connect to %s:%u failed with error %d\n",
                    serverIP_.c_str(), DOIP_PORT, WSAGetLastError());
        CloseSocket(tcpSocket_);
        return;
    }

    DWORD rcvTimeout = TCP_GENERAL_INACTIVITY_TIMEOUT_MS;
    setsockopt(tcpSocket_, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<char*>(&rcvTimeout), sizeof(rcvTimeout));

    LOG_INFO("TCP connection established with %s\n", serverIP_.c_str());
    session_ = DiagSession::Connecting;
}

void DoIPClient::PerformRoutingActivation()
{
    LOG_INFO("Sending Routing_Activ_Req for tester logical address 0x%04X\n",
             TESTER_LOGICAL_ADDR);

    const auto frame = BuildRoutingActivationRequest(TESTER_LOGICAL_ADDR);
    if (!SendFrame(tcpSocket_, frame))
    {
        LOG_VERBOSE("Sending Routing_Activ_Req failed with error %d\n", WSAGetLastError());
        ResetToDiscovery();
        return;
    }

    const auto msg = ReceiveTcpMessage(tcpSocket_);
    if (!msg)
    {
        LOG_VERBOSE("Did not receive Routing_Activ_Res: "
                    "connection lost or response timed out\n");
        ResetToDiscovery();
        return;
    }

    if (msg->type != static_cast<uint16_t>(PayloadType::Routing_Activ_Res))
    {
        LOG_VERBOSE("Expected Routing_Activ_Res (0x%04X) but received type 0x%04X\n",
                    static_cast<uint16_t>(PayloadType::Routing_Activ_Res), msg->type);
        ResetToDiscovery();
        return;
    }

    // TesterAddr(2) | EntityAddr(2) | ResponseCode(1) | Reserved ISO(4) = 9 bytes
    if (msg->payload.size() < 9)
    {
        LOG_VERBOSE("Routing_Activ_Res payload too short: "
                    "%zu bytes (expected >= 9)\n", msg->payload.size());
        ResetToDiscovery();
        return;
    }

    const auto code = RoutingActivResponseCode(*msg);
    if (code != RoutingActivationCode::SuccessfullyActivated &&
        code != RoutingActivationCode::WillBeActivated)
    {
        LOG_VERBOSE("Routing activation denied by server with response code 0x%02X\n",
                    static_cast<uint8_t>(code));
        ResetToDiscovery();
        return;
    }

    LOG_INFO("Routing activation successful\n");
    session_ = DiagSession::ActiveDiagSession;
}

void DoIPClient::PerformDiagnostics()
{
    LOG_INFO("Diagnostic session active. "
             "Type hex UDS bytes (e.g. \"10 01\") and press Enter to send, "
             "or [e] to exit.\n");

    DWORD pollTimeout = DIAG_RECV_POLL_TIMEOUT_MS;
    setsockopt(tcpSocket_, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<char*>(&pollTimeout), sizeof(pollTimeout));

    lastAliveCheck_ = std::chrono::steady_clock::now();

    std::string inputBuffer;
    printf("> ");
    fflush(stdout);

    while (true)
    {
        const auto now = std::chrono::steady_clock::now();
        if (now - lastAliveCheck_ >= std::chrono::milliseconds(ALIVE_CHECK_INTERVAL_MS))
        {
            SendAliveCheck();
            lastAliveCheck_ = std::chrono::steady_clock::now();
        }

        while (_kbhit())
        {
            const char c = static_cast<char>(_getch());

            if (c == '\r' || c == '\n')
            {
                printf("\n");
                if (inputBuffer == "e")
                {
                    LOG_VERBOSE("Exit command received, resetting to discovery\n");
                    ResetToDiscovery();
                    return;
                }
                if (!inputBuffer.empty())
                {
                    const auto udsBytes = ParseHexBytes(inputBuffer);
                    if (udsBytes.empty())
                        LOG_VERBOSE("Could not parse \"%s\" as space-separated hex bytes "
                                    "(e.g. \"10 01\")\n", inputBuffer.c_str());
                    else
                        SendDiagnosticMessage(udsBytes);
                    inputBuffer.clear();
                }
                printf("> ");
                fflush(stdout);
            }
            else if (c == '\b')
            {
                if (!inputBuffer.empty())
                {
                    inputBuffer.pop_back();
                    printf("\b \b");
                    fflush(stdout);
                }
            }
            else
            {
                inputBuffer += c;
                putchar(c);
                fflush(stdout);
            }
        }

        const auto msg = ReceiveTcpMessage(tcpSocket_);
        if (!msg)
        {
            if (WSAGetLastError() == WSAETIMEDOUT)
                continue;
            LOG_VERBOSE("Server connection lost during diagnostics\n");
            ResetToDiscovery();
            return;
        }
        HandleDiagResponse(*msg);
    }
}

void DoIPClient::SendDiagnosticMessage(const std::vector<uint8_t>& udsBytes)
{
    const auto frame = BuildDiagMessage(TESTER_LOGICAL_ADDR,
                                        ENTITY_LOGICAL_ADDR,
                                        udsBytes.data(),
                                        udsBytes.size());
    if (!SendFrame(tcpSocket_, frame))
    {
        LOG_VERBOSE("Sending DIAG_Msg failed with error %d\n", WSAGetLastError());
        return;
    }
    if (LogLevel::INFO >= g_logLevel)
    {
        printf("DIAG_Msg sent to entity 0x%04X, UDS bytes:", ENTITY_LOGICAL_ADDR);
        for (auto b : udsBytes) printf(" %02X", b);
        printf("\n");
    }
}

void DoIPClient::SendAliveCheck()
{
    const auto frame = BuildAliveCheckRequest();
    if (!SendFrame(tcpSocket_, frame))
        LOG_VERBOSE("Sending Alive_Check_Req failed with error %d\n", WSAGetLastError());
    else
        LOG_ALL("Alive_Check_Req sent\n");
}

void DoIPClient::HandleDiagResponse(const DoIPMessage& msg)
{
    switch (static_cast<PayloadType>(msg.type))
    {
    case PayloadType::Generic_DoIP_NACK:
        LOG_VERBOSE("Server rejected last message with Generic_DoIP_NACK code 0x%02X\n",
                    msg.payload.empty() ? 0xFF : msg.payload[0]);
        break;

    case PayloadType::DIAG_Msg_ACK:
        if (msg.payload.size() >= 5)
            LOG_INFO("DIAG_Msg_ACK received from entity 0x%04X, ack code 0x%02X\n",
                     DiagSourceAddr(msg), DiagAckCode(msg));
        else
            LOG_VERBOSE("DIAG_Msg_ACK received with malformed payload "
                        "(%zu bytes, expected >= 5)\n", msg.payload.size());
        break;

    case PayloadType::DIAG_Msg_NACK:
        if (msg.payload.size() >= 5)
            LOG_VERBOSE("DIAG_Msg_NACK received from entity 0x%04X, nack code 0x%02X\n",
                        DiagSourceAddr(msg), msg.payload[4]);
        else
            LOG_VERBOSE("DIAG_Msg_NACK received with malformed payload "
                        "(%zu bytes, expected >= 5)\n", msg.payload.size());
        break;

    case PayloadType::Alive_Check_Res:
        if (msg.payload.size() >= 2)
            LOG_ALL("Alive_Check_Res received from entity 0x%04X\n",
                    AliveCheckEntityAddr(msg));
        else
            LOG_VERBOSE("Alive_Check_Res received with malformed payload "
                        "(%zu bytes, expected >= 2)\n", msg.payload.size());
        break;

    default:
        LOG_VERBOSE("Received unexpected response type 0x%04X\n", msg.type);
        break;
    }
}

std::vector<uint8_t> DoIPClient::ParseHexBytes(const std::string& input)
{
    std::vector<uint8_t> result;
    std::istringstream ss(input);
    std::string token;

    while (ss >> token)
    {
        if (token.size() > 2) return {};
        try
        {
            size_t        pos;
            unsigned long val = std::stoul(token, &pos, 16);
            if (pos != token.size() || val > 0xFF) return {};
            result.push_back(static_cast<uint8_t>(val));
        }
        catch (...) { return {}; }
    }
    return result;
}

int main()
{
    DoIPClient client;
    if (!client.Init()) return 1;
    client.Run();
    return 0;
}
