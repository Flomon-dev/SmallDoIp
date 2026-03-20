#pragma once
#include "log.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

constexpr uint16_t DOIP_PORT              = 13400;
constexpr uint8_t  DOIP_PROTOCOL_VERSION  = 0x02;
constexpr size_t   DOIP_HEADER_SIZE       = 8;
constexpr uint32_t DOIP_MAX_PAYLOAD_BYTES = 4096;
constexpr uint16_t TESTER_LOGICAL_ADDR = 0x0E00;
constexpr uint16_t ENTITY_LOGICAL_ADDR = 0xE000;
constexpr DWORD    TCP_INITIAL_INACTIVITY_TIMEOUT_MS = 2000;
constexpr DWORD    TCP_GENERAL_INACTIVITY_TIMEOUT_MS = 5000;
constexpr uint32_t ALIVE_CHECK_INTERVAL_MS           = 2000;
constexpr DWORD    DIAG_RECV_POLL_TIMEOUT_MS          = 200;

enum class PayloadType : uint16_t
{
    Generic_DoIP_NACK    = 0x0000,
    VehicleIdent_Req     = 0x0001,
    VehicleIdent_Req_EID = 0x0002,
    VehicleIdent_Req_VIN = 0x0003,
    VehicleIdent_Res     = 0x0004,
    Routing_Activ_Req    = 0x0005,
    Routing_Activ_Res    = 0x0006,
    Alive_Check_Req      = 0x0007,
    Alive_Check_Res      = 0x0008,
    DIAG_Msg             = 0x8001,
    DIAG_Msg_NACK        = 0x8002,
    DIAG_Msg_ACK         = 0x8003,
};

enum class GenericNackCode : uint8_t
{
    IncorrectPatternFormat = 0x00,
    UnknownPayloadType     = 0x01,
    MessageTooLarge        = 0x02,
    OutOfMemory            = 0x03,
    InvalidPayloadLength   = 0x04,
};

enum class RoutingActivationCode : uint8_t
{
    DeniedUnknownSourceAddress      = 0x00,
    DeniedAllSocketsRegistered      = 0x01,
    DeniedSAMismatch                = 0x02,
    DeniedSAAlreadyRegistered       = 0x03,
    DeniedMissingAuthentication     = 0x04,
    DeniedRejectedConfirmation      = 0x05,
    DeniedUnsupportedActivationType = 0x06,
    SuccessfullyActivated           = 0x10,
    WillBeActivated                 = 0x11,
};

enum class DiagSession
{
    Discovery,
    Discovered,
    Connecting,
    ActiveDiagSession,
};

// ISO 13400-2 Table 22: fields of a VehicleIdentificationResponse
struct VehicleInfo
{
    std::array<uint8_t, 17> vin          = {};
    uint16_t                logicalAddr  = ENTITY_LOGICAL_ADDR;
    std::array<uint8_t, 6>  eid         = {};
    std::array<uint8_t, 6>  gid         = {};
    uint8_t                 furtherAction = 0x00;
    uint8_t                 syncStatus   = 0x00;
};

struct DoIPMessage
{
    uint16_t             type;
    std::vector<uint8_t> payload;
};

// ── Typed payload accessors (call only after validating payload.size()) ─────────

inline uint16_t PayloadU16At(const DoIPMessage& msg, size_t byteOffset)
{
    uint16_t v;
    std::memcpy(&v, msg.payload.data() + byteOffset, sizeof(v));
    return ntohs(v);
}

// Routing_Activ_Req payload layout: SA(2) | ActivationType(1) | Reserved ISO(4)
inline uint16_t RoutingActivSourceAddr(const DoIPMessage& msg) { return PayloadU16At(msg, 0); }
inline uint8_t  RoutingActivType(const DoIPMessage& msg)       { return msg.payload[2]; }

// Routing_Activ_Res payload layout: TesterAddr(2) | EntityAddr(2) | ResponseCode(1) | Reserved ISO(4)
inline RoutingActivationCode RoutingActivResponseCode(const DoIPMessage& msg)
{
    return static_cast<RoutingActivationCode>(msg.payload[4]);
}

// DIAG_Msg / DIAG_Msg_ACK / DIAG_Msg_NACK payload layout: SA(2) | TA(2) | data / code
inline uint16_t DiagSourceAddr(const DoIPMessage& msg) { return PayloadU16At(msg, 0); }
inline uint16_t DiagTargetAddr(const DoIPMessage& msg) { return PayloadU16At(msg, 2); }
inline uint8_t  DiagAckCode(const DoIPMessage& msg)    { return msg.payload[4]; }

// Alive_Check_Res payload layout: EntityAddr(2)
inline uint16_t AliveCheckEntityAddr(const DoIPMessage& msg) { return PayloadU16At(msg, 0); }

// ── Frame serialization helpers ───────────────────────────────────────────────

inline void AppendBe16(std::vector<uint8_t>& v, uint16_t hostVal)
{
    const uint16_t net = htons(hostVal);
    uint8_t bytes[2];
    std::memcpy(bytes, &net, sizeof(net));
    v.push_back(bytes[0]);
    v.push_back(bytes[1]);
}

inline void AppendBe32(std::vector<uint8_t>& v, uint32_t hostVal)
{
    const uint32_t net = htonl(hostVal);
    uint8_t bytes[4];
    std::memcpy(bytes, &net, sizeof(net));
    v.push_back(bytes[0]);
    v.push_back(bytes[1]);
    v.push_back(bytes[2]);
    v.push_back(bytes[3]);
}

inline void WriteDoIPHeader(std::vector<uint8_t>& frame, PayloadType type, uint32_t payloadLen)
{
    frame.push_back(DOIP_PROTOCOL_VERSION);
    frame.push_back(static_cast<uint8_t>(0xFF ^ DOIP_PROTOCOL_VERSION));
    AppendBe16(frame, static_cast<uint16_t>(type));
    AppendBe32(frame, payloadLen);
}

// ── Frame builders ─────────────────────────────────────────────────────────────

inline std::vector<uint8_t> BuildGenericNack(GenericNackCode code)
{
    std::vector<uint8_t> frame;
    frame.reserve(DOIP_HEADER_SIZE + 1);
    WriteDoIPHeader(frame, PayloadType::Generic_DoIP_NACK, 1);
    frame.push_back(static_cast<uint8_t>(code));
    return frame;
}

inline std::vector<uint8_t> BuildVehicleIdentRequest()
{
    std::vector<uint8_t> frame;
    frame.reserve(DOIP_HEADER_SIZE);
    WriteDoIPHeader(frame, PayloadType::VehicleIdent_Req, 0);
    return frame;
}

// ISO 13400-2 Table 22: VIN(17) + LogicalAddr(2) + EID(6) + GID(6) + FurtherAction(1) + SyncStatus(1)
inline std::vector<uint8_t> BuildVehicleIdentResponse(const VehicleInfo& info)
{
    constexpr uint32_t payloadLen = 17 + 2 + 6 + 6 + 1 + 1;
    std::vector<uint8_t> frame;
    frame.reserve(DOIP_HEADER_SIZE + payloadLen);
    WriteDoIPHeader(frame, PayloadType::VehicleIdent_Res, payloadLen);
    frame.insert(frame.end(), info.vin.begin(), info.vin.end());
    AppendBe16(frame, info.logicalAddr);
    frame.insert(frame.end(), info.eid.begin(), info.eid.end());
    frame.insert(frame.end(), info.gid.begin(), info.gid.end());
    frame.push_back(info.furtherAction);
    frame.push_back(info.syncStatus);
    return frame;
}

// ISO 13400-2 Table 27: SA(2) | ActivationType(1) | Reserved ISO(4)
inline std::vector<uint8_t> BuildRoutingActivationRequest(uint16_t testerAddr,
                                                           uint8_t  activationType = 0x00)
{
    constexpr uint32_t payloadLen = 2 + 1 + 4;
    std::vector<uint8_t> frame;
    frame.reserve(DOIP_HEADER_SIZE + payloadLen);
    WriteDoIPHeader(frame, PayloadType::Routing_Activ_Req, payloadLen);
    AppendBe16(frame, testerAddr);
    frame.push_back(activationType);
    frame.push_back(0x00); // Reserved ISO
    frame.push_back(0x00);
    frame.push_back(0x00);
    frame.push_back(0x00);
    return frame;
}

// ISO 13400-2 Table 28: TesterAddr(2) | EntityAddr(2) | ResponseCode(1) | Reserved ISO(4)
inline std::vector<uint8_t> BuildRoutingActivationResponse(uint16_t              testerAddr,
                                                            uint16_t              entityAddr,
                                                            RoutingActivationCode code)
{
    constexpr uint32_t payloadLen = 2 + 2 + 1 + 4;
    std::vector<uint8_t> frame;
    frame.reserve(DOIP_HEADER_SIZE + payloadLen);
    WriteDoIPHeader(frame, PayloadType::Routing_Activ_Res, payloadLen);
    AppendBe16(frame, testerAddr);
    AppendBe16(frame, entityAddr);
    frame.push_back(static_cast<uint8_t>(code));
    frame.push_back(0x00); // Reserved ISO
    frame.push_back(0x00);
    frame.push_back(0x00);
    frame.push_back(0x00);
    return frame;
}

inline std::vector<uint8_t> BuildAliveCheckRequest()
{
    std::vector<uint8_t> frame;
    frame.reserve(DOIP_HEADER_SIZE);
    WriteDoIPHeader(frame, PayloadType::Alive_Check_Req, 0);
    return frame;
}

// ISO 13400-2 Table 30: EntityAddr(2)
inline std::vector<uint8_t> BuildAliveCheckResponse(uint16_t entityAddr)
{
    constexpr uint32_t payloadLen = 2;
    std::vector<uint8_t> frame;
    frame.reserve(DOIP_HEADER_SIZE + payloadLen);
    WriteDoIPHeader(frame, PayloadType::Alive_Check_Res, payloadLen);
    AppendBe16(frame, entityAddr);
    return frame;
}

// ISO 13400-2 Table 31: SA(2) | TA(2) | UDS data
inline std::vector<uint8_t> BuildDiagMessage(uint16_t       src,
                                              uint16_t       tgt,
                                              const uint8_t* udsData,
                                              size_t         udsLen)
{
    const uint32_t payloadLen = static_cast<uint32_t>(4 + udsLen);
    std::vector<uint8_t> frame;
    frame.reserve(DOIP_HEADER_SIZE + payloadLen);
    WriteDoIPHeader(frame, PayloadType::DIAG_Msg, payloadLen);
    AppendBe16(frame, src);
    AppendBe16(frame, tgt);
    frame.insert(frame.end(), udsData, udsData + udsLen);
    return frame;
}

// ISO 13400-2 Table 33: SA(2) | TA(2) | AckCode(1)
inline std::vector<uint8_t> BuildDiagAck(uint16_t src, uint16_t tgt, uint8_t ackCode)
{
    constexpr uint32_t payloadLen = 5;
    std::vector<uint8_t> frame;
    frame.reserve(DOIP_HEADER_SIZE + payloadLen);
    WriteDoIPHeader(frame, PayloadType::DIAG_Msg_ACK, payloadLen);
    AppendBe16(frame, src);
    AppendBe16(frame, tgt);
    frame.push_back(ackCode);
    return frame;
}

// ── Low-level I/O ─────────────────────────────────────────────────────────────

inline bool RecvExact(SOCKET s, uint8_t* buf, size_t n)
{
    size_t received = 0;
    while (received < n)
    {
        const int r = recv(s,
                           reinterpret_cast<char*>(buf + received),
                           static_cast<int>(n - received),
                           0);
        if (r <= 0) return false;
        received += static_cast<size_t>(r);
    }
    return true;
}

inline bool SendFrame(SOCKET s, const std::vector<uint8_t>& frame)
{
    return send(s,
                reinterpret_cast<const char*>(frame.data()),
                static_cast<int>(frame.size()),
                0) != SOCKET_ERROR;
}

inline void SendTcpNack(SOCKET s, GenericNackCode code)
{
    SendFrame(s, BuildGenericNack(code));
}

inline void SendUdpNack(SOCKET s, const sockaddr_in& to, GenericNackCode code)
{
    const auto frame = BuildGenericNack(code);
    sendto(s,
           reinterpret_cast<const char*>(frame.data()),
           static_cast<int>(frame.size()),
           0,
           reinterpret_cast<const sockaddr*>(&to),
           sizeof(to));
}

// ── Receive & parse ────────────────────────────────────────────────────────────

inline std::optional<DoIPMessage> ParseUdpDatagram(const uint8_t* data, int len)
{
    if (len < static_cast<int>(DOIP_HEADER_SIZE))
    {
        LOG_VERBOSE("UDP datagram too short to contain DoIP header: %d bytes received\n", len);
        return std::nullopt;
    }

    if (data[1] != static_cast<uint8_t>(0xFF ^ data[0]))
    {
        LOG_VERBOSE("Invalid DoIP sync pattern in UDP datagram: "
                    "version=0x%02X inverse=0x%02X\n", data[0], data[1]);
        return std::nullopt;
    }

    uint16_t type;
    std::memcpy(&type, data + 2, sizeof(type));
    type = ntohs(type);

    uint32_t payloadLen;
    std::memcpy(&payloadLen, data + 4, sizeof(payloadLen));
    payloadLen = ntohl(payloadLen);

    if (payloadLen > DOIP_MAX_PAYLOAD_BYTES)
    {
        LOG_VERBOSE("UDP DoIP payload length %u exceeds maximum allowed %u bytes\n",
                    payloadLen, DOIP_MAX_PAYLOAD_BYTES);
        return std::nullopt;
    }

    if (len != static_cast<int>(DOIP_HEADER_SIZE + payloadLen))
    {
        LOG_VERBOSE("UDP datagram is %d bytes but DoIP header declares "
                    "total size of %u bytes\n",
                    len, static_cast<unsigned>(DOIP_HEADER_SIZE + payloadLen));
        return std::nullopt;
    }

    std::vector<uint8_t> payload(data + DOIP_HEADER_SIZE,
                                  data + DOIP_HEADER_SIZE + payloadLen);
    return DoIPMessage{type, std::move(payload)};
}

// Reads one complete DoIP message from a TCP stream. Sends Generic_DoIP_NACK
// and returns nullopt on protocol violations; returns nullopt without NACK on
// connection loss. Callers check WSAGetLastError() to distinguish graceful
// disconnect (0), poll timeout (WSAETIMEDOUT), and hard I/O errors.
inline std::optional<DoIPMessage> ReceiveTcpMessage(SOCKET s)
{
    uint8_t header[DOIP_HEADER_SIZE];
    if (!RecvExact(s, header, DOIP_HEADER_SIZE))
        return std::nullopt;

    if (header[1] != static_cast<uint8_t>(0xFF ^ header[0]))
    {
        LOG_VERBOSE("Invalid DoIP sync pattern: version=0x%02X inverse=0x%02X, "
                    "sending Generic_DoIP_NACK\n", header[0], header[1]);
        SendTcpNack(s, GenericNackCode::IncorrectPatternFormat);
        return std::nullopt;
    }

    uint16_t type;
    std::memcpy(&type, header + 2, sizeof(type));
    type = ntohs(type);

    uint32_t payloadLen;
    std::memcpy(&payloadLen, header + 4, sizeof(payloadLen));
    payloadLen = ntohl(payloadLen);

    if (payloadLen > DOIP_MAX_PAYLOAD_BYTES)
    {
        LOG_VERBOSE("DoIP payload length %u exceeds maximum allowed %u bytes, "
                    "sending Generic_DoIP_NACK\n", payloadLen, DOIP_MAX_PAYLOAD_BYTES);
        SendTcpNack(s, GenericNackCode::MessageTooLarge);
        return std::nullopt;
    }

    std::vector<uint8_t> payload(payloadLen);
    if (payloadLen > 0 && !RecvExact(s, payload.data(), payloadLen))
        return std::nullopt;

    return DoIPMessage{type, std::move(payload)};
}
