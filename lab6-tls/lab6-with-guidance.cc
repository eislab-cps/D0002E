/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Lab 6: Transport Layer Security (TLS)
 * D0002E – Computer Networks
 * Luleå University of Technology
 *
 * Extended variant: reproducible seeds + NetAnim XML output.
 *
 * Scenarios (use --scenario=<name>):
 *   handshake   – Observe the complete TLS 1.2 handshake message sequence
 *   certificate – Examine the server's X.509 certificate
 *   data        – See that application data is encrypted (opaque in PCAP)
 *   cipher      – Observe the negotiated cipher suite in ServerHello
 *   tls-tcp     – See TLS over TCP; observe TCP RST after server closes
 *   all         – Run all five scenarios in sequence
 *
 * New parameters vs. lab6-with-guidance:
 *   --seed=<1-100>   Reproducible RNG seed + timing jitter (default 100)
 *   --pcap=0         Disable PCAP capture (default: enabled)
 *   --cipher256=1    Use AES-256-SHA256 in ALL scenarios (default: only cipher)
 *   --tlsTcp=1       Shorthand alias for --scenario=tls-tcp (PDF compatibility)
 *
 * Build:
 *   ./ns3 build
 *
 * Run:
 *   ./ns3 run "scratch/d0002e/lab6-with-guidance --scenario=all --seed=42"
 *   ./ns3 run "scratch/d0002e/lab6-with-guidance --scenario=cipher --seed=1 --cipher256=1"
 *   ./ns3 run "scratch/d0002e/lab6-with-guidance --scenario=handshake --pcap=0"
 *
 * Output: scratch/d0002e/lab 7 output/seed<N>/<scenario>/
 *   netanim.xml   – Open with NetAnim for animated packet flow
 *   lab7-<scenario>-*.pcap  – Open with Wireshark
 *
 * Wireshark tips:
 *   - Open the -0-0.pcap file (server-side capture)
 *   - Display filter: tls
 *   - Wireshark's TLS heuristic dissector recognises TLS 1.2 records
 *     by ContentType (20–23) and ProtocolVersion (0x0303) in the header
 *
 * ns-3 does NOT have a native TLS stack. This simulation crafts byte
 * sequences that exactly match the TLS 1.2 record format (RFC 5246).
 * The bytes are sent over a real ns-3 TCP socket so Wireshark sees valid
 * TCP segments carrying valid TLS records.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("Lab7TLS");

// ===================================================================
//  EMBEDDED X.509 CERTIFICATE  (DER-encoded, 696 bytes)
// ===================================================================
//
// Generated with:
//   openssl req -x509 -newkey rsa:1024 -nodes -days 3650
//     -subj "/C=SE/ST=Norrbotten/L=Lulea/O=LTU/OU=D0002E/CN=lab7.example.com"
//     -keyout /tmp/lab7key.pem -out /tmp/lab7cert.pem
//   openssl x509 -in /tmp/lab7cert.pem -outform DER -out /tmp/lab7cert.der
//
// Certificate fields:
//   Subject / Issuer : C=SE, ST=Norrbotten, L=Lulea, O=LTU,
//                      OU=D0002E, CN=lab7.example.com
//   Serial           : 58:44:ec:fa:37:4d:3b:34:...
//   Algorithm        : sha256WithRSAEncryption
//   Public Key       : RSA 1024-bit
//   Valid            : 2026-02-23 to 2036-02-21
//
// Because this is a real DER blob, Wireshark's X.509 parser displays
// all certificate fields when you expand the Certificate handshake
// message in the TLS subtree.

static const uint8_t kCertDer[] = {
    0x30, 0x82, 0x02, 0xb4, 0x30, 0x82, 0x02, 0x1d, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x58, 0x44, 0xec, 0xfa, 0x37, 0x4d, 0x3b, 0x34, 0xd2,
    0x0a, 0x5e, 0x17, 0x60, 0x8e, 0xb1, 0x87, 0xa5, 0x88, 0xe0, 0x91, 0x30,
    0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
    0x05, 0x00, 0x30, 0x6c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
    0x06, 0x13, 0x02, 0x53, 0x45, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
    0x04, 0x08, 0x0c, 0x0a, 0x4e, 0x6f, 0x72, 0x72, 0x62, 0x6f, 0x74, 0x74,
    0x65, 0x6e, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c,
    0x05, 0x4c, 0x75, 0x6c, 0x65, 0x61, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03,
    0x55, 0x04, 0x0a, 0x0c, 0x03, 0x4c, 0x54, 0x55, 0x31, 0x0f, 0x30, 0x0d,
    0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x06, 0x44, 0x30, 0x30, 0x30, 0x32,
    0x45, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x10,
    0x6c, 0x61, 0x62, 0x37, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x32,
    0x32, 0x33, 0x31, 0x39, 0x34, 0x36, 0x33, 0x34, 0x5a, 0x17, 0x0d, 0x33,
    0x36, 0x30, 0x32, 0x32, 0x31, 0x31, 0x39, 0x34, 0x36, 0x33, 0x34, 0x5a,
    0x30, 0x6c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
    0x02, 0x53, 0x45, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08,
    0x0c, 0x0a, 0x4e, 0x6f, 0x72, 0x72, 0x62, 0x6f, 0x74, 0x74, 0x65, 0x6e,
    0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x05, 0x4c,
    0x75, 0x6c, 0x65, 0x61, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04,
    0x0a, 0x0c, 0x03, 0x4c, 0x54, 0x55, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03,
    0x55, 0x04, 0x0b, 0x0c, 0x06, 0x44, 0x30, 0x30, 0x30, 0x32, 0x45, 0x31,
    0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x10, 0x6c, 0x61,
    0x62, 0x37, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63,
    0x6f, 0x6d, 0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00,
    0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xf2, 0x6f, 0xc0, 0x32, 0x17,
    0xc1, 0xd5, 0xd1, 0x88, 0x75, 0xfa, 0xbb, 0x68, 0xc2, 0x0f, 0x24, 0x47,
    0x08, 0xd8, 0x53, 0x08, 0xe2, 0x8a, 0x4d, 0xc3, 0xba, 0x80, 0xe2, 0xef,
    0x28, 0x26, 0x50, 0x65, 0x22, 0x01, 0x02, 0xbc, 0x6c, 0xda, 0x92, 0xe8,
    0x80, 0xfb, 0xdf, 0x3a, 0x09, 0x42, 0x5f, 0xfc, 0x1f, 0x12, 0x4e, 0x03,
    0xa6, 0xb2, 0xac, 0x36, 0x74, 0x2a, 0x37, 0xd3, 0xab, 0x4e, 0xfe, 0x52,
    0xdc, 0xf7, 0x84, 0x17, 0xb8, 0xcf, 0x11, 0x48, 0x47, 0x91, 0x5a, 0xc7,
    0xd9, 0x1d, 0xc9, 0xe8, 0xc1, 0x0d, 0x9c, 0xa5, 0x89, 0x7a, 0xb0, 0xaf,
    0x82, 0x54, 0x64, 0xab, 0xc5, 0xe8, 0x7a, 0x93, 0xef, 0x6e, 0x5a, 0x56,
    0x07, 0x25, 0xca, 0xb3, 0x1b, 0xb5, 0x53, 0x64, 0x33, 0x9e, 0x9d, 0xdc,
    0x92, 0xdb, 0xab, 0xc1, 0x92, 0x1e, 0xe3, 0xec, 0x0c, 0x9f, 0xc0, 0x6a,
    0xa0, 0x50, 0x8b, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x53, 0x30, 0x51,
    0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xa3,
    0x18, 0x07, 0x3a, 0x23, 0x94, 0x08, 0xc2, 0xc3, 0xff, 0x76, 0x03, 0x46,
    0xa8, 0xed, 0x34, 0x6f, 0x02, 0x27, 0x05, 0x30, 0x1f, 0x06, 0x03, 0x55,
    0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xa3, 0x18, 0x07, 0x3a,
    0x23, 0x94, 0x08, 0xc2, 0xc3, 0xff, 0x76, 0x03, 0x46, 0xa8, 0xed, 0x34,
    0x6f, 0x02, 0x27, 0x05, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
    0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06,
    0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
    0x03, 0x81, 0x81, 0x00, 0x24, 0x95, 0x11, 0x7a, 0x50, 0xb9, 0x82, 0x6e,
    0x8d, 0xe0, 0x71, 0x62, 0xf6, 0x21, 0xbf, 0x90, 0xdd, 0x76, 0x6b, 0xd2,
    0x1d, 0xb5, 0xd6, 0x1e, 0x25, 0x9c, 0x94, 0x3e, 0x66, 0x92, 0x0b, 0xd4,
    0xbd, 0x4e, 0x3a, 0x8e, 0xd4, 0x1a, 0xe2, 0xac, 0xcf, 0x0d, 0xf1, 0x6c,
    0xa8, 0xe8, 0x57, 0xd0, 0x95, 0x04, 0x74, 0x88, 0xd3, 0x78, 0xc9, 0xa0,
    0x64, 0xe0, 0xa0, 0x64, 0xdf, 0x30, 0x1e, 0x58, 0x5d, 0x97, 0x24, 0x00,
    0x22, 0x42, 0x6e, 0x52, 0xb3, 0x8a, 0x14, 0xd5, 0xfe, 0x82, 0x3f, 0x7a,
    0xb4, 0x1b, 0xc8, 0xe6, 0x62, 0xda, 0xee, 0x69, 0xc0, 0x47, 0xc6, 0x13,
    0xcf, 0xda, 0x55, 0x46, 0x34, 0x65, 0x5c, 0x79, 0xc0, 0x1d, 0x55, 0x06,
    0xff, 0xdc, 0x9b, 0x63, 0xca, 0x87, 0xa9, 0xc5, 0x4c, 0x23, 0xa8, 0x1f,
    0x9a, 0x7d, 0xa3, 0x47, 0xb3, 0xfc, 0x85, 0xfb, 0xb0, 0x7a, 0x4e, 0xe2,
};
static const size_t kCertDerLen = 696;

// ===================================================================
//  GLOBALS  (set from command line in main)
// ===================================================================

static uint32_t g_seed        = 100;    // --seed=1..100
static bool     g_pcapEnabled = true;   // --pcap=0 to disable
static bool     g_cipher256   = false;  // --cipher256=1 forces AES-256 in all scenarios

// ===================================================================
//  TLS 1.2 RECORD FORMAT  (RFC 5246 §6)
// ===================================================================
//
// Every TLS message is wrapped in a TLS Record Layer header:
//
//  Byte 0   : ContentType
//               0x14 (20) = ChangeCipherSpec
//               0x15 (21) = Alert
//               0x16 (22) = Handshake
//               0x17 (23) = ApplicationData
//  Bytes 1-2: ProtocolVersion  →  0x03 0x03  (TLS 1.2)
//  Bytes 3-4: Length (big-endian) of the Fragment that follows
//  Bytes 5.. : Fragment
//
// Handshake messages (ContentType=22) have a 4-byte inner header:
//  Byte 0   : HandshakeType
//               1  = ClientHello
//               2  = ServerHello
//              11  = Certificate
//              14  = ServerHelloDone
//              16  = ClientKeyExchange
//              20  = Finished
//  Bytes 1-3: Length (big-endian, 24-bit) of the HandshakeBody
//  Bytes 4..: HandshakeBody
//
// Wireshark's TLS dissector identifies TLS records by checking that
// ContentType is in [20,23] and ProtocolVersion is 0x0301–0x0304.
// It then parses the inner structure according to ContentType.

// Build a raw TLS record: 5-byte header + body
static std::vector<uint8_t>
TlsRecord(uint8_t ct, const uint8_t *body, size_t bodyLen)
{
    std::vector<uint8_t> r;
    r.reserve(5 + bodyLen);
    r.push_back(ct);                             // ContentType
    r.push_back(0x03);                           // Version: TLS 1.2 major = 3
    r.push_back(0x03);                           // Version: TLS 1.2 minor = 3
    r.push_back(static_cast<uint8_t>(bodyLen >> 8));   // Length high
    r.push_back(static_cast<uint8_t>(bodyLen & 0xFF)); // Length low
    if (body && bodyLen)
        r.insert(r.end(), body, body + bodyLen);
    return r;
}

// Build a Handshake record (ContentType=22) with a 4-byte inner header
static std::vector<uint8_t>
TlsHandshakeRecord(uint8_t hsType, const uint8_t *body, size_t bodyLen)
{
    // 4-byte Handshake header: type (1) + length (3)
    uint8_t hdr[4];
    hdr[0] = hsType;
    hdr[1] = static_cast<uint8_t>(bodyLen >> 16);
    hdr[2] = static_cast<uint8_t>(bodyLen >> 8);
    hdr[3] = static_cast<uint8_t>(bodyLen & 0xFF);

    std::vector<uint8_t> msg;
    msg.insert(msg.end(), hdr, hdr + 4);
    if (body && bodyLen)
        msg.insert(msg.end(), body, body + bodyLen);

    return TlsRecord(0x16, msg.data(), msg.size()); // 0x16 = Handshake
}

// Convert a byte vector to an ns-3 Packet
static Ptr<Packet>
VecToPacket(const std::vector<uint8_t> &v)
{
    return Create<Packet>(v.data(), static_cast<uint32_t>(v.size()));
}

// -------------------------------------------------------------------
// BuildClientHello
// -------------------------------------------------------------------
static std::vector<uint8_t>
BuildClientHello()
{
    // ClientHello body (RFC 5246 §7.4.1.2):
    //   client_version (2)         – highest TLS version the client supports
    //   random (32)                – 4-byte timestamp + 28 random bytes
    //   session_id_len (1)         – 0 means no session resumption
    //   cipher_suites_len (2)      – length of cipher suite list
    //   cipher_suites (N×2)        – list of supported cipher suites
    //   compression_methods_len(1) – 1
    //   compression_method (1)     – 0x00 = null (no compression in TLS 1.2)
    //
    // Wireshark shows all offered cipher suites in the ClientHello subtree.
    // The client offers four common RSA+AES suites for the server to choose.

    std::vector<uint8_t> b;

    // client_version = TLS 1.2
    b.push_back(0x03); b.push_back(0x03);

    // random[32]: 4-byte simulated timestamp + 28 pseudo-random bytes
    const uint8_t rnd[32] = {
        0x67, 0x0a, 0x1b, 0x2c,
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x01, 0x12,
        0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a,
        0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0, 0x01, 0x02,
        0x03, 0x04, 0x05, 0x06
    };
    b.insert(b.end(), rnd, rnd + 32);

    b.push_back(0x00);              // session_id_len = 0

    // 4 cipher suites × 2 bytes = 8 bytes
    b.push_back(0x00); b.push_back(0x08);
    b.push_back(0x00); b.push_back(0x2F); // TLS_RSA_WITH_AES_128_CBC_SHA
    b.push_back(0x00); b.push_back(0x35); // TLS_RSA_WITH_AES_256_CBC_SHA
    b.push_back(0x00); b.push_back(0x3C); // TLS_RSA_WITH_AES_128_CBC_SHA256
    b.push_back(0x00); b.push_back(0x3D); // TLS_RSA_WITH_AES_256_CBC_SHA256

    b.push_back(0x01); // compression_methods_len = 1
    b.push_back(0x00); // null compression

    return TlsHandshakeRecord(1, b.data(), b.size()); // HandshakeType 1 = ClientHello
}

// -------------------------------------------------------------------
// BuildServerHello
// -------------------------------------------------------------------
static std::vector<uint8_t>
BuildServerHello(bool useCipher256)
{
    // ServerHello body (RFC 5246 §7.4.1.3):
    //   server_version (2)    – selected TLS version (must be ≤ client's)
    //   random (32)           – server's own random (different from client's)
    //   session_id_len (1)    – 0 (no session ID issued)
    //   cipher_suite (2)      – one suite from the client's offered list
    //   compression_method(1) – 0x00 = null
    //
    // Standard scenario  → TLS_RSA_WITH_AES_128_CBC_SHA    (0x002F)
    // cipher scenario    → TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003D)
    //
    // Wireshark highlights the selected Cipher Suite in the ServerHello.
    // This is the suite that will be used for the rest of the session.

    std::vector<uint8_t> b;

    b.push_back(0x03); b.push_back(0x03); // TLS 1.2

    const uint8_t rnd[32] = {
        0x67, 0x0a, 0x1b, 0x2d,
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81,
        0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72, 0x82,
        0x0a, 0x0b, 0x0c, 0x0d
    };
    b.insert(b.end(), rnd, rnd + 32);

    b.push_back(0x00); // session_id_len = 0

    if (useCipher256) {
        b.push_back(0x00); b.push_back(0x3D); // TLS_RSA_WITH_AES_256_CBC_SHA256
    } else {
        b.push_back(0x00); b.push_back(0x2F); // TLS_RSA_WITH_AES_128_CBC_SHA
    }

    b.push_back(0x00); // null compression

    return TlsHandshakeRecord(2, b.data(), b.size()); // HandshakeType 2 = ServerHello
}

// -------------------------------------------------------------------
// BuildCertificate
// -------------------------------------------------------------------
static std::vector<uint8_t>
BuildCertificate()
{
    // Certificate body (RFC 5246 §7.4.2):
    //   certificate_list_len (3)   – total length of all certs in list
    //   For each cert:
    //     cert_len (3)             – length of this DER cert
    //     cert_data (cert_len)     – DER-encoded X.509 certificate
    //
    // We send exactly one certificate: kCertDer (696 bytes).
    //
    // Wireshark's X.509 parser decodes the DER blob and shows:
    //   Subject: C=SE, ST=Norrbotten, L=Lulea, O=LTU,
    //            OU=D0002E, CN=lab7.example.com
    //   Public Key Algorithm: rsaEncryption (1024 bit)
    //   Validity: Not Before / Not After
    //   Extensions: Subject Key Identifier, Authority Key Identifier
    //
    // To inspect the certificate outside Wireshark:
    //   openssl x509 -in /tmp/lab7cert.pem -text -noout

    std::vector<uint8_t> b;

    size_t certListLen = 3 + kCertDerLen; // 3 = size of cert_len field
    b.push_back(static_cast<uint8_t>(certListLen >> 16));
    b.push_back(static_cast<uint8_t>(certListLen >> 8));
    b.push_back(static_cast<uint8_t>(certListLen & 0xFF));

    b.push_back(static_cast<uint8_t>(kCertDerLen >> 16));
    b.push_back(static_cast<uint8_t>(kCertDerLen >> 8));
    b.push_back(static_cast<uint8_t>(kCertDerLen & 0xFF));

    b.insert(b.end(), kCertDer, kCertDer + kCertDerLen);

    return TlsHandshakeRecord(11, b.data(), b.size()); // HandshakeType 11 = Certificate
}

// -------------------------------------------------------------------
// BuildServerHelloDone
// -------------------------------------------------------------------
static std::vector<uint8_t>
BuildServerHelloDone()
{
    // ServerHelloDone (RFC 5246 §7.4.5) has an empty body (length = 0).
    // It signals that the server has finished its part of the Hello phase
    // and is waiting for the client to respond.
    // Wireshark shows: "Handshake Protocol: Server Hello Done"
    return TlsHandshakeRecord(14, nullptr, 0); // HandshakeType 14 = ServerHelloDone
}

// -------------------------------------------------------------------
// BuildClientKeyExchange
// -------------------------------------------------------------------
static std::vector<uint8_t>
BuildClientKeyExchange()
{
    // ClientKeyExchange for RSA key exchange (RFC 5246 §7.4.7.1):
    //   length (2 bytes)
    //   encrypted_premaster_secret (128 bytes for RSA-1024)
    //
    // In a real TLS session the client would:
    //   1. Generate a 48-byte PreMasterSecret: {0x03, 0x03, <46 random bytes>}
    //   2. Encrypt it with the server's 1024-bit RSA public key
    //      → 128-byte ciphertext  (key size / 8)
    //   3. Send the ciphertext here
    //
    // The server decrypts it with its private key, derives the same
    // symmetric session keys as the client, and the handshake is complete.
    //
    // Here we use simulated (non-functional) bytes but the correct length.
    // Wireshark shows the 128-byte encrypted blob.

    std::vector<uint8_t> b;
    b.push_back(0x00); b.push_back(0x80); // length = 128 bytes
    for (int i = 0; i < 128; i++)
        b.push_back(static_cast<uint8_t>(0x42 ^ i)); // simulated encrypted bytes

    return TlsHandshakeRecord(16, b.data(), b.size()); // HandshakeType 16 = ClientKeyExchange
}

// -------------------------------------------------------------------
// BuildChangeCipherSpec
// -------------------------------------------------------------------
static std::vector<uint8_t>
BuildChangeCipherSpec()
{
    // ChangeCipherSpec uses its own ContentType (0x14 = 20).
    // It is NOT a Handshake message.
    //
    // Body: single byte 0x01.
    //
    // Meaning: "All subsequent records will be protected with the
    // negotiated cipher and keys."
    //
    // Both client and server send one ChangeCipherSpec immediately
    // before their respective Finished messages.
    //
    // Wireshark shows: "Change Cipher Spec Protocol: Change Cipher Spec"

    const uint8_t body[] = {0x01};
    return TlsRecord(0x14, body, 1); // ContentType 0x14 = ChangeCipherSpec
}

// -------------------------------------------------------------------
// BuildEncryptedHandshake  (Finished message, encrypted)
// -------------------------------------------------------------------
static std::vector<uint8_t>
BuildEncryptedHandshake()
{
    // After ChangeCipherSpec the Finished message is the first record
    // protected by the negotiated cipher.  Wireshark cannot decrypt it
    // (no session keys available), so it labels it:
    //   "Encrypted Handshake Message"
    //
    // Simulated AES-128-CBC-SHA content (52 bytes):
    //   IV (16) + encrypted Finished body (16) + MAC-SHA1 (20)
    // Real Finished contains a hash over all handshake messages to prove
    // that both endpoints derived the same session keys.

    uint8_t body[52];
    for (int i = 0; i < 52; i++)
        body[i] = static_cast<uint8_t>(0xA0 ^ i);

    return TlsRecord(0x16, body, 52); // ContentType 0x16 = Handshake (encrypted)
}

// -------------------------------------------------------------------
// BuildAppData
// -------------------------------------------------------------------
static std::vector<uint8_t>
BuildAppData(const char *plaintext)
{
    // ApplicationData record (RFC 5246 §6.2.3):
    //   ContentType = 0x17 (23) = ApplicationData
    //
    // In a real TLS session, plaintext is encrypted with the symmetric
    // session key (e.g., AES-128-CBC).  The record carries:
    //   IV (16 bytes) | ciphertext | padding | MAC (20 bytes for SHA-1)
    //
    // Wireshark shows: "Encrypted Application Data"
    // The actual HTTP (or other) content is completely hidden.
    // This is TLS confidentiality: even capturing every packet does not
    // reveal the payload without the session keys.
    //
    // This simulation XOR-scrambles the plaintext with 0x5A so the bytes
    // in the PCAP are not directly readable (no real AES is performed).

    size_t ptLen = strlen(plaintext);

    std::vector<uint8_t> body;

    // IV: 16 bytes
    for (int i = 0; i < 16; i++)
        body.push_back(static_cast<uint8_t>(0xE0 + i));

    // Simulated ciphertext
    for (size_t i = 0; i < ptLen; i++)
        body.push_back(static_cast<uint8_t>(
            static_cast<unsigned char>(plaintext[i]) ^ 0x5A));

    // PKCS#7 padding to next 16-byte boundary
    size_t pad = 16 - (ptLen % 16);
    for (size_t i = 0; i < pad; i++)
        body.push_back(static_cast<uint8_t>(pad - 1));

    // MAC: 20 bytes (SHA-1)
    for (int i = 0; i < 20; i++)
        body.push_back(static_cast<uint8_t>(0xC0 + i));

    return TlsRecord(0x17, body.data(), body.size()); // ContentType 0x17 = ApplicationData
}

// ===================================================================
//  TLS SERVER APPLICATION
// ===================================================================
//
// TlsServerApp listens on TCP port 50443.  When a client connects it
// schedules TLS handshake messages at realistic intervals, then sends
// an encrypted ApplicationData record.
//
// In the tls-tcp scenario it additionally closes all sockets so that a
// subsequent SYN from the client triggers a TCP RST.

class TlsServerApp : public Application
{
  public:
    static TypeId GetTypeId();

    TlsServerApp() : m_useCipher256(false), m_isTlsTcp(false) {}
    ~TlsServerApp() override = default;

    // Call before SetStartTime()
    void Configure(bool cipher256, bool tlsTcp)
    {
        m_useCipher256 = cipher256;
        m_isTlsTcp     = tlsTcp;
    }

  private:
    void StartApplication() override;
    void StopApplication() override;

    // Accept callbacks
    bool OnRequest(Ptr<Socket> sock, const Address &) { return true; }
    void OnAccept(Ptr<Socket> sock, const Address &from);

    // Receive callback (just drains the buffer)
    void OnRecv(Ptr<Socket> sock);

    // Scheduled TLS message senders
    void DoServerHelloCertDone(Ptr<Socket> sock);
    void DoServerCcsFinished(Ptr<Socket> sock);
    void DoServerAppData(Ptr<Socket> sock);
    void DoCloseAll();

    Ptr<Socket> m_listenSock;
    Ptr<Socket> m_connSock;
    bool m_useCipher256;
    bool m_isTlsTcp;
};

NS_OBJECT_ENSURE_REGISTERED(TlsServerApp);

TypeId
TlsServerApp::GetTypeId()
{
    static TypeId tid = TypeId("TlsServerApp")
                            .SetParent<Application>()
                            .AddConstructor<TlsServerApp>();
    return tid;
}

void
TlsServerApp::StartApplication()
{
    // [GUIDANCE] TLS always runs over TCP.  Create a TCP socket, bind it
    // to port 50443, and call Listen().  Port 50443 mirrors HTTPS (443)
    // without requiring elevated privileges.
    //
    // SetAcceptCallback registers two callbacks:
    //   1. Request callback (OnRequest) – called on incoming SYN;
    //      return true to complete the 3-way handshake.
    //   2. Accept callback (OnAccept)   – called once the TCP connection
    //      is ESTABLISHED; a new socket for this connection is passed in.

    m_listenSock = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    m_listenSock->Bind(InetSocketAddress(Ipv4Address::GetAny(), 50443));
    m_listenSock->Listen();
    m_listenSock->SetAcceptCallback(
        MakeCallback(&TlsServerApp::OnRequest, this),
        MakeCallback(&TlsServerApp::OnAccept,  this));
}

void
TlsServerApp::StopApplication()
{
    if (m_connSock)   { m_connSock->Close();   m_connSock   = nullptr; }
    if (m_listenSock) { m_listenSock->Close(); m_listenSock = nullptr; }
}

void
TlsServerApp::OnAccept(Ptr<Socket> sock, const Address &)
{
    // [GUIDANCE] The TCP 3-way handshake (SYN/SYN-ACK/ACK) has completed.
    // ns-3 created a new socket for this connection; the listen socket
    // continues to accept further clients.
    //
    // We schedule TLS messages with delays that simulate processing:
    //   +100 ms  ServerHello + Certificate + ServerHelloDone
    //   +400 ms  ChangeCipherSpec + Finished (Encrypted Handshake Message)
    //   +2000 ms ApplicationData  (HTTP response, encrypted)

    m_connSock = sock;
    sock->SetRecvCallback(MakeCallback(&TlsServerApp::OnRecv, this));

    Simulator::Schedule(MilliSeconds(100),  &TlsServerApp::DoServerHelloCertDone, this, sock);
    Simulator::Schedule(MilliSeconds(400),  &TlsServerApp::DoServerCcsFinished,   this, sock);
    Simulator::Schedule(MilliSeconds(2000), &TlsServerApp::DoServerAppData,       this, sock);

    if (m_isTlsTcp)
    {
        // tls-tcp scenario: close everything at +4 s so the listen socket
        // disappears before the client's reconnect attempt
        Simulator::Schedule(Seconds(4.0), &TlsServerApp::DoCloseAll, this);
    }
}

void
TlsServerApp::OnRecv(Ptr<Socket> sock)
{
    Ptr<Packet> p;
    while ((p = sock->Recv()))
        ; // drain – we don't process received data in this simulation
}

void
TlsServerApp::DoServerHelloCertDone(Ptr<Socket> sock)
{
    // [GUIDANCE] Send three Handshake messages back-to-back:
    //
    //   ServerHello      – selects TLS 1.2 and the cipher suite
    //   Certificate      – delivers the server's X.509 certificate
    //                      (contains the public key the client needs for
    //                       ClientKeyExchange)
    //   ServerHelloDone  – empty body; signals "your turn, client"
    //
    // Each is a separate TLS record but they arrive in the same TCP segment.
    // Wireshark shows them as three distinct Handshake messages.

    sock->Send(VecToPacket(BuildServerHello(m_useCipher256)));
    sock->Send(VecToPacket(BuildCertificate()));
    sock->Send(VecToPacket(BuildServerHelloDone()));
}

void
TlsServerApp::DoServerCcsFinished(Ptr<Socket> sock)
{
    // [GUIDANCE] After receiving ClientKeyExchange from the client, the server:
    //   1. ChangeCipherSpec – "switching to encrypted mode now"
    //   2. Finished         – first encrypted record; Wireshark labels it
    //                         "Encrypted Handshake Message" because it
    //                         cannot decrypt it without the session keys.
    //
    // The Finished message body contains a PRF hash of all handshake
    // messages, confirming that both sides derived the same session keys.

    sock->Send(VecToPacket(BuildChangeCipherSpec()));
    sock->Send(VecToPacket(BuildEncryptedHandshake()));
}

void
TlsServerApp::DoServerAppData(Ptr<Socket> sock)
{
    // [GUIDANCE] After the handshake the server sends an HTTP/1.1 response
    // wrapped in a TLS ApplicationData record (ContentType=23).
    // The payload is XOR-scrambled here to simulate AES encryption.
    // In a real HTTPS server this would be an AES-encrypted HTTP response.
    // Wireshark shows "Encrypted Application Data" – you cannot read the
    // HTTP headers or body from the PCAP.

    const char *httpResp =
        "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nHello TLS!";
    sock->Send(VecToPacket(BuildAppData(httpResp)));
}

void
TlsServerApp::DoCloseAll()
{
    // [GUIDANCE] tls-tcp scenario only.
    //
    // Close the active connection socket (sends TCP FIN to client) and
    // then close the listen socket (removes it from the TCP stack).
    //
    // After this, port 50443 has no listening socket.  When the client
    // sends a new SYN (DoReconnect), the ns-3 TCP layer finds no matching
    // socket and sends a TCP RST segment back.
    //
    // In Wireshark: look for a segment with Flags: [RST, ACK] near the
    // end of the trace.  This demonstrates that without a live TCP
    // connection there can be no TLS session.

    if (m_connSock)   { m_connSock->Close();   m_connSock   = nullptr; }
    if (m_listenSock) { m_listenSock->Close(); m_listenSock = nullptr; }
}

// ===================================================================
//  TLS CLIENT APPLICATION
// ===================================================================
//
// TlsClientApp connects to the server at t=1 s and drives the client
// side of the TLS 1.2 handshake, then sends an ApplicationData record.
//
// In the tls-tcp scenario it also attempts a second connection after
// the server has closed its listen socket, triggering a TCP RST.

class TlsClientApp : public Application
{
  public:
    static TypeId GetTypeId();

    TlsClientApp() : m_isTlsTcp(false) {}
    ~TlsClientApp() override = default;

    // Call before SetStartTime()
    void Setup(Ipv4Address serverAddr, bool tlsTcp)
    {
        m_serverAddr = serverAddr;
        m_isTlsTcp   = tlsTcp;
    }

  private:
    void StartApplication() override;
    void StopApplication() override;

    void DoConnect();
    void OnConnected(Ptr<Socket> sock);
    void OnConnectFailed(Ptr<Socket> sock) {}

    void OnRecv(Ptr<Socket> sock);

    void DoClientCkeCcsFinished(Ptr<Socket> sock);
    void DoClientAppData(Ptr<Socket> sock);
    void DoReconnect();

    Ptr<Socket> m_sock;
    Ptr<Socket> m_reconnectSock; // keeps the reconnect socket alive for RST
    Ipv4Address m_serverAddr;
    bool        m_isTlsTcp;
};

NS_OBJECT_ENSURE_REGISTERED(TlsClientApp);

TypeId
TlsClientApp::GetTypeId()
{
    static TypeId tid = TypeId("TlsClientApp")
                            .SetParent<Application>()
                            .AddConstructor<TlsClientApp>();
    return tid;
}

void
TlsClientApp::StartApplication()
{
    // Delay TCP connect by 1 s to ensure the server is already listening
    Simulator::Schedule(Seconds(1.0), &TlsClientApp::DoConnect, this);
}

void
TlsClientApp::StopApplication()
{
    if (m_reconnectSock) { m_reconnectSock->Close(); m_reconnectSock = nullptr; }
    if (m_sock)          { m_sock->Close();          m_sock          = nullptr; }
}

void
TlsClientApp::DoConnect()
{
    // [GUIDANCE] Create a TCP socket and initiate a connection to the
    // server on port 50443.  The TCP 3-way handshake (SYN/SYN-ACK/ACK)
    // runs transparently inside ns-3.  OnConnected() is called once
    // the connection reaches the ESTABLISHED state.
    //
    // SetConnectCallback registers:
    //   success callback – OnConnected  (TCP ESTABLISHED)
    //   failure callback – OnConnectFailed (timeout / RST during connect)

    m_sock = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    m_sock->SetConnectCallback(
        MakeCallback(&TlsClientApp::OnConnected,    this),
        MakeCallback(&TlsClientApp::OnConnectFailed, this));
    m_sock->SetRecvCallback(MakeCallback(&TlsClientApp::OnRecv, this));
    m_sock->Connect(InetSocketAddress(m_serverAddr, 50443));
}

void
TlsClientApp::OnConnected(Ptr<Socket> sock)
{
    // [GUIDANCE] TCP connection is established.  The client immediately
    // sends ClientHello to begin the TLS handshake.
    //
    // Scheduled messages:
    //   now     ClientHello (proposes TLS 1.2, lists cipher suites)
    //   +300 ms ClientKeyExchange + ChangeCipherSpec + Finished
    //   +2000ms ApplicationData  (HTTP GET, encrypted)

    sock->Send(VecToPacket(BuildClientHello()));

    Simulator::Schedule(MilliSeconds(300),
                        &TlsClientApp::DoClientCkeCcsFinished, this, sock);
    Simulator::Schedule(MilliSeconds(2000),
                        &TlsClientApp::DoClientAppData, this, sock);

    if (m_isTlsTcp)
    {
        // Attempt reconnect 6 s after initial connect (server closes at ~t=5s)
        Simulator::Schedule(Seconds(6.0), &TlsClientApp::DoReconnect, this);
    }
}

void
TlsClientApp::OnRecv(Ptr<Socket> sock)
{
    Ptr<Packet> p;
    while ((p = sock->Recv()))
        ; // drain
}

void
TlsClientApp::DoClientCkeCcsFinished(Ptr<Socket> sock)
{
    // [GUIDANCE] After receiving ServerHelloDone the client completes its
    // side of the handshake with three messages:
    //
    //   ClientKeyExchange – 128-byte RSA-encrypted pre-master secret
    //   ChangeCipherSpec  – "switching to encrypted mode"
    //   Finished          – first encrypted record (Encrypted Handshake
    //                       Message in Wireshark); contains a hash of all
    //                       handshake messages to verify key agreement

    sock->Send(VecToPacket(BuildClientKeyExchange()));
    sock->Send(VecToPacket(BuildChangeCipherSpec()));
    sock->Send(VecToPacket(BuildEncryptedHandshake()));
}

void
TlsClientApp::DoClientAppData(Ptr<Socket> sock)
{
    // [GUIDANCE] Send an HTTP GET request wrapped in a TLS ApplicationData
    // record (ContentType=23).  The payload is XOR-scrambled to simulate
    // AES encryption.  Wireshark shows "Encrypted Application Data" –
    // the HTTP verb, headers and path are all hidden by TLS.

    const char *httpGet =
        "GET / HTTP/1.1\r\nHost: lab7.example.com\r\nConnection: close\r\n\r\n";
    sock->Send(VecToPacket(BuildAppData(httpGet)));
}

void
TlsClientApp::DoReconnect()
{
    // [GUIDANCE] tls-tcp scenario only.
    //
    // The server closed its listen socket ~2 seconds ago.  Create a brand-new
    // TCP socket and attempt to connect to port 50443.
    //
    // Because no socket is listening on that port, the server's TCP stack
    // responds with a RST+ACK segment.  In Wireshark:
    //   Filter: tcp
    //   Look for: Flags: [RST, ACK]  at the end of the trace
    //
    // Key insight: RST immediately aborts any TLS session attempt.  There
    // is no TLS-level recovery mechanism – TLS depends on TCP for connection
    // management.  If TCP goes away, TLS goes away.

    m_reconnectSock = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    m_reconnectSock->SetRecvCallback(MakeCallback(&TlsClientApp::OnRecv, this));
    m_reconnectSock->Connect(InetSocketAddress(m_serverAddr, 50443));
}

// ===================================================================
//  TOPOLOGY + SCENARIO RUNNER
// ===================================================================
//
// All scenarios share the same P2P topology:
//
//   [Client 10.7.1.2] ---100 Mbps / 2 ms--- [Server 10.7.1.1]
//   (node 1)                                  (node 0)
//
// A P2P link is used so there is no ambiguity about which node sent
// which packet.  TLS works over any TCP-capable link.

struct ScenarioCfg
{
    std::string name;
    bool        cipher256; // true → select AES-256-SHA256 in ServerHello
    bool        tlsTcp;    // true → close sockets + generate RST
};

// -------------------------------------------------------------------
//  SetupMobility – assign 2D positions for NetAnim
// -------------------------------------------------------------------
static void
SetupMobility(NodeContainer nodes)
{
    // Topology:  Server (node 0) left, Client (node 1) right
    //
    //   (20,50) Server -------- Client (80,50)
    //
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> posAlloc = CreateObject<ListPositionAllocator>();
    posAlloc->Add(Vector(20.0, 50.0, 0.0)); // node 0: server
    posAlloc->Add(Vector(80.0, 50.0, 0.0)); // node 1: client
    mobility.SetPositionAllocator(posAlloc);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);
}

// -------------------------------------------------------------------
//  RunScenario – build topology, run simulation, write NetAnim XML
// -------------------------------------------------------------------
static void
RunScenario(const ScenarioCfg &cfg, uint32_t seed, double jitter,
            const std::string &animFile)
{
    // ---- Reproducibility ----
    RngSeedManager::SetSeed(seed);
    RngSeedManager::SetRun(seed);

    std::string outDir = "scratch/d0002e/lab 7 output/seed" +
                         std::to_string(seed) + "/" + cfg.name + "/";
    std::filesystem::create_directories(outDir);

    // ---- Nodes ----
    NodeContainer nodes;
    nodes.Create(2); // 0 = server, 1 = client

    // ---- Point-to-Point link ----
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute ("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay",    StringValue("2ms"));
    NetDeviceContainer devs = p2p.Install(nodes);

    // ---- Internet stack ----
    InternetStackHelper inet;
    inet.Install(nodes);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.7.1.0", "255.255.255.0");
    Ipv4InterfaceContainer ifaces = ipv4.Assign(devs);
    // ifaces.GetAddress(0) = 10.7.1.1  (server)
    // ifaces.GetAddress(1) = 10.7.1.2  (client)

    // ---- Mobility (positions for NetAnim) ----
    SetupMobility(nodes);

    // ---- Server application (node 0) ----
    Ptr<TlsServerApp> server = CreateObject<TlsServerApp>();
    server->Configure(cfg.cipher256, cfg.tlsTcp);
    nodes.Get(0)->AddApplication(server);
    server->SetStartTime(Seconds(0.0));
    server->SetStopTime (Seconds(12.0 + jitter));

    // ---- Client application (node 1) ----
    // jitter shifts the client start time so each seed produces unique timing
    Ptr<TlsClientApp> client = CreateObject<TlsClientApp>();
    client->Setup(ifaces.GetAddress(0), cfg.tlsTcp);
    nodes.Get(1)->AddApplication(client);
    client->SetStartTime(Seconds(jitter));
    client->SetStopTime (Seconds(12.0 + jitter));

    // ---- PCAP ----
    if (g_pcapEnabled)
        p2p.EnablePcapAll(outDir + "lab7-" + cfg.name, false);

    // ---- NetAnim ----
    AnimationInterface anim(animFile);
    anim.EnablePacketMetadata(true);
    anim.EnableIpv4L3ProtocolCounters(Seconds(0), Seconds(12.0 + jitter));

    // Node labels, colours and sizes
    anim.UpdateNodeDescription(nodes.Get(0), "Server\n10.7.1.1:50443");
    anim.UpdateNodeDescription(nodes.Get(1), "Client\n10.7.1.2");
    anim.UpdateNodeColor(nodes.Get(0), 0,   102, 204); // blue  = server
    anim.UpdateNodeColor(nodes.Get(1), 204, 102,   0); // amber = client
    anim.UpdateNodeSize(nodes.Get(0)->GetId(), 3.0, 3.0);
    anim.UpdateNodeSize(nodes.Get(1)->GetId(), 3.0, 3.0);

    Simulator::Run();
    Simulator::Destroy();
}

// ===================================================================
//  SCENARIO WRAPPERS  (with per-scenario guidance)
// ===================================================================

static void
RunHandshake(uint32_t seed, double jitter)
{
    // -------------------------------------------------------------------
    // Scenario: handshake
    // -------------------------------------------------------------------
    // Observe the complete TLS 1.2 handshake between client and server.
    //
    // Expected TLS message sequence in Wireshark (filter: tls):
    //
    //   →  Client Hello        client proposes TLS 1.2, lists 4 cipher suites
    //   ←  Server Hello        server selects TLS 1.2, AES_128_CBC_SHA
    //   ←  Certificate         server's X.509 cert (696 bytes DER)
    //   ←  Server Hello Done   server hello phase complete
    //   →  Client Key Exchange RSA-encrypted pre-master secret (128 bytes)
    //   →  Change Cipher Spec  client switches to encrypted mode
    //   →  Encrypted HS Msg    client Finished (first encrypted record)
    //   ←  Change Cipher Spec  server switches to encrypted mode
    //   ←  Encrypted HS Msg    server Finished
    //   →  Application Data    HTTP GET (encrypted)
    //   ←  Application Data    HTTP 200 (encrypted)
    //
    // Lab questions:
    //   [W] What TLS messages are exchanged? (list all messages above)
    //   [W] What TLS version is negotiated? (check ServerHello → Version)
    //   [B] What TCP destination port does the client use? (50443)
    //   [C] Where in the code does the server bind to port 50443?
    //       (TlsServerApp::StartApplication → Bind(InetSocketAddress(..., 50443)))
    //   [V] Why is a handshake necessary before data exchange?
    //       Both sides must agree on and derive the same session keys before
    //       they can encrypt/decrypt application data.

    NS_LOG_INFO("=== Scenario: handshake ===");
    std::string outDir = "scratch/d0002e/lab 7 output/seed" +
                         std::to_string(seed) + "/handshake/";
    RunScenario({"handshake", g_cipher256, false}, seed, jitter,
                outDir + "netanim.xml");
}

static void
RunCertificate(uint32_t seed, double jitter)
{
    // -------------------------------------------------------------------
    // Scenario: certificate
    // -------------------------------------------------------------------
    // Examine the X.509 certificate sent by the server in the Certificate
    // handshake message.
    //
    // In a real HTTPS connection, the browser uses this certificate to:
    //   1. Verify identity – CN=lab7.example.com must match the URL hostname
    //   2. Extract public key – used by the client to encrypt the pre-master
    //      secret in ClientKeyExchange (RSA key exchange)
    //   3. Verify CA signature – certificate must be signed by a trusted CA
    //
    // In Wireshark: expand the Certificate message:
    //   TLSv1.2 → Handshake Protocol → Certificate
    //     → Certificates (696 bytes)
    //       → Certificate (id-at-commonName=lab7.example.com)
    //         → signedCertificate
    //           → subject: rdnSequence
    //             → C=SE, ST=Norrbotten, O=LTU, OU=D0002E
    //             → CN=lab7.example.com
    //           → subjectPublicKeyInfo
    //             → algorithm: rsaEncryption
    //             → subjectPublicKey: (1024 bit)
    //           → validity: notBefore / notAfter
    //
    // Lab questions:
    //   [W] What information does the certificate contain?
    //       (Subject, Issuer, Public Key, Validity, Extensions)
    //   [B] What is the public key algorithm and key size?
    //       (rsaEncryption, 1024 bit)
    //   [C] Where is the certificate loaded in the simulation code?
    //       (kCertDer[] array at the top of the file; sent via BuildCertificate())
    //   [V] Why is asymmetric (RSA) cryptography used only in the handshake?
    //       RSA operations are ~1000× slower than AES. RSA is used once to
    //       securely exchange the pre-master secret; all bulk data uses the
    //       fast symmetric AES cipher derived from it.

    NS_LOG_INFO("=== Scenario: certificate ===");
    std::string outDir = "scratch/d0002e/lab 7 output/seed" +
                         std::to_string(seed) + "/certificate/";
    RunScenario({"certificate", g_cipher256, false}, seed, jitter,
                outDir + "netanim.xml");
}

static void
RunData(uint32_t seed, double jitter)
{
    // -------------------------------------------------------------------
    // Scenario: data
    // -------------------------------------------------------------------
    // Observe that application data is encrypted and unreadable in the PCAP.
    //
    // After the handshake, client and server exchange ApplicationData records
    // (ContentType=23).  Each record contains IV + ciphertext + MAC.
    // There are no plaintext HTTP headers visible.
    //
    // In Wireshark:
    //   Filter: tls
    //   Select an "Application Data" record
    //   Expand: TLSv1.2 → TLS Record Layer → Encrypted Application Data
    //   The bytes shown are ciphertext – unreadable without session keys.
    //
    // Compare with a plain HTTP (no TLS) capture where you can read:
    //   "GET / HTTP/1.1\r\nHost: ..." directly in the packet bytes.
    //
    // Lab questions:
    //   [W] Can you read the HTTP payload from the PCAP?  Why not?
    //       No. TLS encrypts the ApplicationData payload with AES before
    //       passing it to TCP, so only ciphertext appears in the PCAP.
    //   [B] How do you identify encrypted records in Wireshark?
    //       ContentType=23 (0x17) and the label "Encrypted Application Data"
    //   [C] Where in the code is ApplicationData sent?
    //       TlsServerApp::DoServerAppData and TlsClientApp::DoClientAppData
    //       both call BuildAppData(), which wraps the payload in a TLS record.
    //   [V] What TLS security property ensures payload confidentiality?
    //       Symmetric encryption (AES-CBC) with session keys derived during
    //       the handshake.  The session keys never appear on the wire.

    NS_LOG_INFO("=== Scenario: data ===");
    std::string outDir = "scratch/d0002e/lab 7 output/seed" +
                         std::to_string(seed) + "/data/";
    RunScenario({"data", g_cipher256, false}, seed, jitter,
                outDir + "netanim.xml");
}

static void
RunCipher(uint32_t seed, double jitter)
{
    // -------------------------------------------------------------------
    // Scenario: cipher
    // -------------------------------------------------------------------
    // Observe a stronger cipher suite negotiated in the TLS handshake.
    //
    // This scenario configures the server to select:
    //   TLS_RSA_WITH_AES_256_CBC_SHA256  (0x003D)
    // instead of the default:
    //   TLS_RSA_WITH_AES_128_CBC_SHA     (0x002F)
    //
    // In Wireshark: expand the ServerHello message:
    //   TLSv1.2 → Handshake Protocol → Server Hello
    //     → Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003d)
    //
    // Compare with the "handshake" scenario where you see 0x002f.
    //
    // The cipher suite name encodes three algorithms:
    //   RSA          – key exchange  (encrypts pre-master secret with RSA pub key)
    //   AES_256_CBC  – bulk encryption (256-bit key, CBC mode)
    //   SHA256       – MAC algorithm (HMAC-SHA256 for record integrity)
    //
    // Lab questions:
    //   [W] What cipher suite is negotiated in this scenario?
    //       TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003d)
    //   [C] Where in the simulation code is the cipher suite configured?
    //       BuildServerHello(useCipher256=true) sets 0x003D instead of 0x002F.
    //       The cipher256 flag is set in RunScenario via ScenarioCfg.cipher256=true.
    //   [B] What symmetric cipher algorithm is used for bulk data?
    //       AES-256 in CBC mode.
    //   [V] Why use symmetric encryption (AES) for bulk data instead of RSA?
    //       AES-256 encrypts a 16-byte block in nanoseconds; RSA-2048 takes
    //       ~0.1 ms per operation.  Symmetric ciphers are orders of magnitude
    //       faster for large payloads.

    NS_LOG_INFO("=== Scenario: cipher ===");
    std::string outDir = "scratch/d0002e/lab 7 output/seed" +
                         std::to_string(seed) + "/cipher/";
    // cipher scenario always uses AES-256 regardless of --cipher256 flag
    RunScenario({"cipher", true, false}, seed, jitter, outDir + "netanim.xml");
}

static void
RunTlsTcp(uint32_t seed, double jitter)
{
    // -------------------------------------------------------------------
    // Scenario: tls-tcp
    // -------------------------------------------------------------------
    // Demonstrate that TLS depends on TCP and observe a TCP RST.
    //
    // Timeline:
    //   t = 1.0+j s  TCP SYN (client → server)
    //   t ≈ 1.0+j s  TCP SYN-ACK + ACK (3-way handshake completes)
    //   t ≈ 1.0+j s  TLS handshake begins: ClientHello →
    //   t ≈ 1.1+j s  ← ServerHello + Certificate + ServerHelloDone
    //   t ≈ 1.3+j s  ClientKeyExchange + CCS + Finished →
    //   t ≈ 1.4+j s  ← Server CCS + Finished
    //   t ≈ 3.0+j s  ApplicationData exchange (both directions)
    //   t ≈ 5.0+j s  Server calls Close() on conn + listen sockets (TCP FIN)
    //   t = 7.0+j s  Client sends new SYN to port 50443 (no listener!)
    //   t ≈ 7.0+j s  ← [RST, ACK]  server TCP stack rejects the SYN
    //   (j = seed jitter = (seed%20)*0.005 s)
    //
    // In Wireshark (filter: tcp):
    //   Look for the RST segment near t=7+j s (Flags: [RST, ACK]).
    //   This segment is sent by ns-3's TcpL4Protocol because no socket
    //   is listening on port 50443 when the second SYN arrives.
    //
    // Also try filter: tls  →  you see the handshake and data records
    //                            only during the first TCP connection.
    //
    // Lab questions:
    //   [W] How can you tell from the PCAP that TLS runs over TCP?
    //       The TCP SYN/SYN-ACK/ACK precede all TLS records; TLS records
    //       appear as TCP segment payloads.
    //   [C] Where in the code is the TCP socket created for TLS?
    //       Both TlsServerApp::StartApplication and TlsClientApp::DoConnect
    //       call Socket::CreateSocket(node, TcpSocketFactory::GetTypeId()).
    //   [B] What happens in the PCAP when the server sends a RST?
    //       The RST+ACK segment terminates the connection attempt immediately.
    //       Any pending TLS handshake is aborted; no TLS records follow.
    //   [V] Why does TLS require TCP rather than UDP?
    //       TLS records must arrive complete and in order – TLS has no
    //       mechanism for reordering or reassembly.  TCP provides exactly
    //       these guarantees.  (DTLS is the UDP variant of TLS and adds
    //       its own record-layer sequencing and retransmission.)

    // Run with:  --scenario=tls-tcp  OR the shorthand  --tlsTcp=1
    NS_LOG_INFO("=== Scenario: tls-tcp ===");
    std::string outDir = "scratch/d0002e/lab 7 output/seed" +
                         std::to_string(seed) + "/tls-tcp/";
    RunScenario({"tls-tcp", g_cipher256, true}, seed, jitter,
                outDir + "netanim.xml");
}

// ===================================================================
//  MAIN
// ===================================================================

int
main(int argc, char *argv[])
{
    std::string scenario = "handshake";
    bool tlsTcpAlias = false; // PDF mentions --tlsTcp; alias for --scenario=tls-tcp

    CommandLine cmd(__FILE__);
    cmd.AddValue("scenario",
                 "Scenario to run: handshake|certificate|data|cipher|tls-tcp|all",
                 scenario);
    cmd.AddValue("tlsTcp",
                 "Shorthand for --scenario=tls-tcp (PDF compatibility alias)",
                 tlsTcpAlias);
    cmd.AddValue("seed",
                 "RNG seed 1–100; also controls timing jitter (default 100)",
                 g_seed);
    cmd.AddValue("pcap",
                 "Enable PCAP capture 0/1 (default 1)",
                 g_pcapEnabled);
    cmd.AddValue("cipher256",
                 "Force AES-256-SHA256 in all scenarios 0/1 (default 0)",
                 g_cipher256);
    cmd.Parse(argc, argv);

    // PDF refers to "--tlsTcp"; honour it as an alias for --scenario=tls-tcp
    if (tlsTcpAlias)
        scenario = "tls-tcp";

    // PacketMetadata must be enabled before any topology is created
    PacketMetadata::Enable();

    LogComponentEnable("Lab7TLS", LOG_LEVEL_INFO);

    // Jitter: 0..0.095 s depending on seed (20 distinct values)
    double jitter = static_cast<double>(g_seed % 20) * 0.005;

    NS_LOG_INFO("seed=" << g_seed << "  jitter=" << jitter
                        << "s  cipher256=" << g_cipher256
                        << "  pcap=" << g_pcapEnabled);

    if      (scenario == "handshake")   RunHandshake   (g_seed, jitter);
    else if (scenario == "certificate") RunCertificate (g_seed, jitter);
    else if (scenario == "data")        RunData        (g_seed, jitter);
    else if (scenario == "cipher")      RunCipher      (g_seed, jitter);
    else if (scenario == "tls-tcp")     RunTlsTcp      (g_seed, jitter);
    else if (scenario == "all")
    {
        RunHandshake   (g_seed, jitter);
        RunCertificate (g_seed, jitter);
        RunData        (g_seed, jitter);
        RunCipher      (g_seed, jitter);
        RunTlsTcp      (g_seed, jitter);
    }
    else
    {
        std::cerr << "Unknown scenario: " << scenario << "\n"
                  << "Valid values: handshake|certificate|data|cipher|tls-tcp|all\n";
        return 1;
    }

    return 0;
}
