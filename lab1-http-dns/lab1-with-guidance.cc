/*
 * =============================================================================
 * ns-3 Wireshark Lab Simulation - HTTP and DNS
 * =============================================================================
 *
 * This script generates PCAP files for Wireshark HTTP and DNS lab exercises.
 * Based on Kurose & Ross "Computer Networking: A Top-Down Approach" labs v8.0.
 *
 * =============================================================================
 * HOW TO RUN EACH SCENARIO
 * =============================================================================
 *
 * Build:
 *   ./ns3 build scratch/d0002e/lab1
 *
 * Run scenarios (outputs go to "scratch/d0002e/lab 1 output/"):
 *
 * 1) BASIC HTTP GET/RESPONSE (HTTP Lab Section 1):
 *    ./ns3 run "scratch/d0002e/lab1 --scenario=basic"
 *    PCAP: client-*.pcap - Shows GET request and 200 OK response
 *
 * 2) CONDITIONAL GET (HTTP Lab Section 2):
 *    ./ns3 run "scratch/d0002e/lab1 --scenario=conditional"
 *    PCAP: client-*.pcap - Shows first GET with 200 OK + Last-Modified,
 *          then second GET with If-Modified-Since and 304 Not Modified
 *
 * 3) LONG DOCUMENT (HTTP Lab Section 3):
 *    ./ns3 run "scratch/d0002e/lab1 --scenario=long"
 *    PCAP: client-*.pcap - Shows GET and response spanning multiple TCP segments
 *
 * 4) EMBEDDED OBJECTS (HTTP Lab Section 4):
 *    ./ns3 run "scratch/d0002e/lab1 --scenario=embedded --parallel=false"
 *    ./ns3 run "scratch/d0002e/lab1 --scenario=embedded --parallel=true"
 *    PCAP: client-*.pcap - Shows base HTML fetch, then image fetches from
 *          two different servers (serial or parallel)
 *
 * 5) HTTP AUTHENTICATION (HTTP Lab Section 5):
 *    ./ns3 run "scratch/d0002e/lab1 --scenario=auth"
 *    PCAP: client-*.pcap - Shows GET, 401 Unauthorized with WWW-Authenticate,
 *          then GET with Authorization: Basic header, then 200 OK
 *
 * 6) DNS QUERIES (DNS Lab):
 *    ./ns3 run "scratch/d0002e/lab1 --scenario=dns"
 *    PCAP: client-*.pcap, dns-server-*.pcap - Shows Type A and Type NS queries
 *
 * 7) ALL SCENARIOS:
 *    ./ns3 run "scratch/d0002e/lab1 --scenario=all"
 *
 * Additional options:
 *   --verbose=true      Enable detailed logging
 *   --dnsTTL=300        DNS cache TTL in seconds (default: 300)
 *   --mss=536           TCP MSS for long document test (default: 536)
 *
 * =============================================================================
 * NETWORK TOPOLOGY
 * =============================================================================
 *
 *                      +------------------+
 *                      |   DNS Server     |
 *                      |   (n1)           |
 *                      |   10.1.1.2       |
 *                      +--------+---------+
 *                               |
 *   +-------------+    +--------+---------+    +------------------+
 *   |   Client    |    |                  |    |  HTTP Server 1   |
 *   |   (n0)      +----+   CSMA Switch    +----+  (n2)            |
 *   |   10.1.1.1  |    |   (100 Mbps)     |    |  10.1.1.3        |
 *   +-------------+    +--------+---------+    +------------------+
 *                               |
 *                      +--------+---------+
 *                      |  HTTP Server 2   |
 *                      |  (n3)            |
 *                      |  10.1.1.4        |
 *                      +------------------+
 *
 * =============================================================================
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"

#include <filesystem>
#include <cstring>
#include <map>
#include <sstream>
#include <iomanip>
#include <ctime>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("WiresharkLab");

// Output directory (note: contains space as per requirement)
static const std::string outputDir = "scratch/d0002e/lab 1 output/";

// =============================================================================
// Relevant to DNS Caching: g_dnsTTL controls DNS cache Time-To-Live
// Relevant to DNS and HTTP Interaction: Lowering TTL increases DNS query frequency
// =============================================================================
static uint32_t g_dnsTTL = 300;

// =============================================================================
// Relevant to Long Document Retrieval: g_tcpMss affects TCP segmentation
// A smaller MSS increases the number of TCP segments for large responses
// =============================================================================
static uint32_t g_tcpMss = 536;

// =============================================================================
// Relevant to Embedded Objects: g_parallelDownload controls serial vs parallel fetching
// =============================================================================
static bool g_parallelDownload = false;

// =============================================================================
// Relevant to HTTP Authentication: Base64 encoding for HTTP Basic Auth credentials
// Base64 is used per HTTP Basic authentication specification (RFC 7617)
// =============================================================================

static const std::string base64Chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string Base64Encode(const std::string& input)
{
    std::string output;
    int val = 0, valb = -6;
    for (unsigned char c : input)
    {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0)
        {
            output.push_back(base64Chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
    {
        output.push_back(base64Chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (output.size() % 4)
    {
        output.push_back('=');
    }
    return output;
}

// =============================================================================
// DNS PROTOCOL HELPERS
// =============================================================================

// =============================================================================
// Relevant to Query Types: DNS record type constants used to select query type
// =============================================================================
enum DnsType : uint16_t
{
    DNS_TYPE_A = 1,    // Address record (IPv4)
    DNS_TYPE_NS = 2,   // Name server record
    DNS_TYPE_CNAME = 5,
    DNS_TYPE_MX = 15,
    DNS_TYPE_AAAA = 28 // IPv6 address
};

// Encode hostname as DNS labels (RFC 1035 format)
void EncodeDnsName(std::vector<uint8_t>& buffer, const std::string& hostname)
{
    size_t pos = 0;
    while (pos < hostname.length())
    {
        size_t dotPos = hostname.find('.', pos);
        if (dotPos == std::string::npos)
        {
            dotPos = hostname.length();
        }
        size_t labelLen = dotPos - pos;
        buffer.push_back(static_cast<uint8_t>(labelLen));
        for (size_t i = pos; i < dotPos; ++i)
        {
            buffer.push_back(static_cast<uint8_t>(hostname[i]));
        }
        pos = dotPos + 1;
    }
    buffer.push_back(0x00);
}

// =============================================================================
// Relevant to DNS and HTTP Interaction: Transaction ID is placed in the DNS header
// The client generates the ID and the server copies it into the response
// =============================================================================
Ptr<Packet> CreateDnsQuery(uint16_t transactionId, const std::string& hostname, uint16_t qtype)
{
    std::vector<uint8_t> buffer;

    // DNS Header (12 bytes)
    // Relevant to DNS and HTTP Interaction: Transaction ID bytes
    buffer.push_back((transactionId >> 8) & 0xFF);
    buffer.push_back(transactionId & 0xFF);
    // Flags: Standard query, recursion desired (0x0100)
    buffer.push_back(0x01);
    buffer.push_back(0x00);
    // Questions: 1
    buffer.push_back(0x00);
    buffer.push_back(0x01);
    // Answer RRs: 0
    buffer.push_back(0x00);
    buffer.push_back(0x00);
    // Authority RRs: 0
    buffer.push_back(0x00);
    buffer.push_back(0x00);
    // Additional RRs: 0
    buffer.push_back(0x00);
    buffer.push_back(0x00);

    // Question section
    EncodeDnsName(buffer, hostname);
    // Relevant to Query Types: Query type (A=1, NS=2, etc.) encoded here
    buffer.push_back((qtype >> 8) & 0xFF);
    buffer.push_back(qtype & 0xFF);
    // Class: IN (0x0001)
    buffer.push_back(0x00);
    buffer.push_back(0x01);

    return Create<Packet>(buffer.data(), buffer.size());
}

// =============================================================================
// Relevant to Basic DNS Queries: Creates DNS response with A record answers
// Each answer contains an IPv4 address
// =============================================================================
Ptr<Packet> CreateDnsResponseA(uint16_t transactionId, const std::string& hostname,
                                const std::vector<std::string>& ipAddresses, uint32_t ttl)
{
    std::vector<uint8_t> buffer;

    // DNS Header - Transaction ID copied from query
    buffer.push_back((transactionId >> 8) & 0xFF);
    buffer.push_back(transactionId & 0xFF);
    // Flags: Standard response, recursion available (0x8180)
    buffer.push_back(0x81);
    buffer.push_back(0x80);
    // Questions: 1
    buffer.push_back(0x00);
    buffer.push_back(0x01);
    // Answer RRs - number of IP addresses returned
    buffer.push_back((ipAddresses.size() >> 8) & 0xFF);
    buffer.push_back(ipAddresses.size() & 0xFF);
    // Authority RRs: 0
    buffer.push_back(0x00);
    buffer.push_back(0x00);
    // Additional RRs: 0
    buffer.push_back(0x00);
    buffer.push_back(0x00);

    // Question section (echoed back)
    size_t questionStart = buffer.size();
    EncodeDnsName(buffer, hostname);
    buffer.push_back(0x00);
    buffer.push_back(0x01); // Type A
    buffer.push_back(0x00);
    buffer.push_back(0x01); // Class IN

    // Answer section(s) - one for each IP address
    for (const auto& ip : ipAddresses)
    {
        // Name pointer to question (offset 12)
        buffer.push_back(0xC0);
        buffer.push_back(0x0C);
        // Type: A
        buffer.push_back(0x00);
        buffer.push_back(0x01);
        // Class: IN
        buffer.push_back(0x00);
        buffer.push_back(0x01);
        // TTL - controls DNS caching duration
        buffer.push_back((ttl >> 24) & 0xFF);
        buffer.push_back((ttl >> 16) & 0xFF);
        buffer.push_back((ttl >> 8) & 0xFF);
        buffer.push_back(ttl & 0xFF);
        // Data length: 4 (IPv4)
        buffer.push_back(0x00);
        buffer.push_back(0x04);
        // IP address
        uint32_t a, b, c, d;
        sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
        buffer.push_back(static_cast<uint8_t>(a));
        buffer.push_back(static_cast<uint8_t>(b));
        buffer.push_back(static_cast<uint8_t>(c));
        buffer.push_back(static_cast<uint8_t>(d));
    }

    return Create<Packet>(buffer.data(), buffer.size());
}

// =============================================================================
// Relevant to DNS and HTTP Interaction: NS queries return multiple nameservers
// This function creates a DNS response with NS records and glue A records
// =============================================================================
Ptr<Packet> CreateDnsResponseNS(uint16_t transactionId, const std::string& domain,
                                 const std::vector<std::pair<std::string, std::string>>& nameservers,
                                 uint32_t ttl)
{
    std::vector<uint8_t> buffer;

    // DNS Header
    buffer.push_back((transactionId >> 8) & 0xFF);
    buffer.push_back(transactionId & 0xFF);
    // Flags: Standard response, recursion available
    buffer.push_back(0x81);
    buffer.push_back(0x80);
    // Questions: 1
    buffer.push_back(0x00);
    buffer.push_back(0x01);
    // Answer RRs - multiple NS records
    buffer.push_back((nameservers.size() >> 8) & 0xFF);
    buffer.push_back(nameservers.size() & 0xFF);
    // Authority RRs: 0
    buffer.push_back(0x00);
    buffer.push_back(0x00);
    // Additional RRs (glue records for NS IPs)
    buffer.push_back((nameservers.size() >> 8) & 0xFF);
    buffer.push_back(nameservers.size() & 0xFF);

    // Question section
    EncodeDnsName(buffer, domain);
    buffer.push_back(0x00);
    buffer.push_back(0x02); // Type NS
    buffer.push_back(0x00);
    buffer.push_back(0x01); // Class IN

    // Answer section - NS records (multiple answers for authoritative nameservers)
    std::vector<size_t> nsOffsets;
    for (const auto& ns : nameservers)
    {
        // Name pointer to domain
        buffer.push_back(0xC0);
        buffer.push_back(0x0C);
        // Type: NS
        buffer.push_back(0x00);
        buffer.push_back(0x02);
        // Class: IN
        buffer.push_back(0x00);
        buffer.push_back(0x01);
        // TTL
        buffer.push_back((ttl >> 24) & 0xFF);
        buffer.push_back((ttl >> 16) & 0xFF);
        buffer.push_back((ttl >> 8) & 0xFF);
        buffer.push_back(ttl & 0xFF);

        // Calculate RDATA length
        size_t rdataLen = 0;
        std::string nsName = ns.first;
        size_t pos = 0;
        while (pos < nsName.length())
        {
            size_t dotPos = nsName.find('.', pos);
            if (dotPos == std::string::npos) dotPos = nsName.length();
            rdataLen += 1 + (dotPos - pos);
            pos = dotPos + 1;
        }
        rdataLen += 1; // null terminator

        buffer.push_back((rdataLen >> 8) & 0xFF);
        buffer.push_back(rdataLen & 0xFF);

        nsOffsets.push_back(buffer.size());
        EncodeDnsName(buffer, nsName);
    }

    // Additional section - A records for nameservers (glue records)
    for (size_t i = 0; i < nameservers.size(); ++i)
    {
        // Name pointer to NS name in answer
        buffer.push_back(0xC0);
        buffer.push_back(static_cast<uint8_t>(nsOffsets[i]));
        // Type: A
        buffer.push_back(0x00);
        buffer.push_back(0x01);
        // Class: IN
        buffer.push_back(0x00);
        buffer.push_back(0x01);
        // TTL
        buffer.push_back((ttl >> 24) & 0xFF);
        buffer.push_back((ttl >> 16) & 0xFF);
        buffer.push_back((ttl >> 8) & 0xFF);
        buffer.push_back(ttl & 0xFF);
        // Data length: 4
        buffer.push_back(0x00);
        buffer.push_back(0x04);
        // IP address
        uint32_t a, b, c, d;
        sscanf(nameservers[i].second.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
        buffer.push_back(static_cast<uint8_t>(a));
        buffer.push_back(static_cast<uint8_t>(b));
        buffer.push_back(static_cast<uint8_t>(c));
        buffer.push_back(static_cast<uint8_t>(d));
    }

    return Create<Packet>(buffer.data(), buffer.size());
}

// =============================================================================
// DNS CACHE
// =============================================================================
// Relevant to DNS Caching: DnsCacheEntry stores resolved addresses with expiry time
// =============================================================================

struct DnsCacheEntry
{
    std::vector<std::string> addresses;
    Time expiry;  // Cache entry expires after TTL seconds
};

// =============================================================================
// Relevant to DNS Caching: DnsCache class implements client-side DNS caching
// Responses are stored with TTL and reused until expiration
// =============================================================================
class DnsCache
{
  public:
    // Relevant to DNS Caching: Lookup checks if hostname is cached and not expired
    // To disable caching, this lookup could be bypassed
    bool Lookup(const std::string& hostname, std::vector<std::string>& result)
    {
        auto it = m_cache.find(hostname);
        if (it != m_cache.end() && it->second.expiry > Simulator::Now())
        {
            result = it->second.addresses;
            NS_LOG_INFO("DNS Cache HIT for " << hostname);
            return true;
        }
        NS_LOG_INFO("DNS Cache MISS for " << hostname);
        return false;
    }

    // Relevant to DNS Caching: Store saves DNS response with TTL-based expiry
    void Store(const std::string& hostname, const std::vector<std::string>& addresses, uint32_t ttl)
    {
        DnsCacheEntry entry;
        entry.addresses = addresses;
        entry.expiry = Simulator::Now() + Seconds(ttl);
        m_cache[hostname] = entry;
        NS_LOG_INFO("DNS Cache stored " << hostname << " with TTL " << ttl);
    }

    void Flush()
    {
        m_cache.clear();
        NS_LOG_INFO("DNS Cache flushed");
    }

  private:
    std::map<std::string, DnsCacheEntry> m_cache;
};

// Global DNS cache
static DnsCache g_dnsCache;

// =============================================================================
// DNS SERVER APPLICATION
// =============================================================================
// Relevant to Basic DNS Queries: DnsServerApp listens on port 53 for DNS queries
// =============================================================================

class DnsServerApp : public Application
{
  public:
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("DnsServerApp")
                                .SetParent<Application>()
                                .SetGroupName("Tutorial")
                                .AddConstructor<DnsServerApp>();
        return tid;
    }

    DnsServerApp() : m_socket(nullptr), m_nextTransId(0x1000) {}
    ~DnsServerApp() override { m_socket = nullptr; }

    // Configure DNS records
    void AddARecord(const std::string& hostname, const std::vector<std::string>& ips)
    {
        m_aRecords[hostname] = ips;
    }

    void AddNSRecord(const std::string& domain,
                     const std::vector<std::pair<std::string, std::string>>& nameservers)
    {
        m_nsRecords[domain] = nameservers;
    }

  protected:
    void StartApplication() override
    {
        if (!m_socket)
        {
            m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
            // Relevant to Basic DNS Queries: DNS server binds to port 53
            InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), 53);
            m_socket->Bind(local);
        }
        m_socket->SetRecvCallback(MakeCallback(&DnsServerApp::HandleRead, this));
    }

    void StopApplication() override
    {
        if (m_socket)
        {
            m_socket->Close();
            m_socket->SetRecvCallback(MakeNullCallback<void, Ptr<Socket>>());
        }
    }

  private:
    void HandleRead(Ptr<Socket> socket)
    {
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom(from)))
        {
            if (packet->GetSize() >= 12)
            {
                uint8_t header[12];
                packet->CopyData(header, 12);
                uint16_t transId = (header[0] << 8) | header[1];
                uint16_t flags = (header[2] << 8) | header[3];
                uint16_t qdcount = (header[4] << 8) | header[5];

                if (qdcount > 0)
                {
                    // Parse question
                    uint8_t qbuf[256];
                    packet->CopyData(qbuf, std::min((uint32_t)256, packet->GetSize()));

                    std::string qname;
                    size_t pos = 12;
                    while (pos < packet->GetSize() && qbuf[pos] != 0)
                    {
                        uint8_t len = qbuf[pos++];
                        if (!qname.empty()) qname += ".";
                        for (uint8_t i = 0; i < len && pos < packet->GetSize(); ++i)
                        {
                            qname += static_cast<char>(qbuf[pos++]);
                        }
                    }
                    pos++; // skip null
                    // Relevant to Query Types: Extract query type from DNS question
                    uint16_t qtype = (qbuf[pos] << 8) | qbuf[pos + 1];

                    NS_LOG_INFO("DNS Server: Query for " << qname << " type " << qtype);

                    Ptr<Packet> response;
                    if (qtype == DNS_TYPE_A)
                    {
                        auto it = m_aRecords.find(qname);
                        if (it != m_aRecords.end())
                        {
                            response = CreateDnsResponseA(transId, qname, it->second, g_dnsTTL);
                        }
                        else
                        {
                            // Return NXDOMAIN or empty response
                            response = CreateDnsResponseA(transId, qname, {}, 0);
                        }
                    }
                    else if (qtype == DNS_TYPE_NS)
                    {
                        // Relevant to DNS and HTTP Interaction: NS queries return multiple nameservers
                        auto it = m_nsRecords.find(qname);
                        if (it != m_nsRecords.end())
                        {
                            response = CreateDnsResponseNS(transId, qname, it->second, g_dnsTTL);
                        }
                        else
                        {
                            // Try to find parent domain
                            std::string domain = qname;
                            while (!domain.empty())
                            {
                                auto it2 = m_nsRecords.find(domain);
                                if (it2 != m_nsRecords.end())
                                {
                                    response = CreateDnsResponseNS(transId, domain, it2->second, g_dnsTTL);
                                    break;
                                }
                                size_t dotPos = domain.find('.');
                                if (dotPos != std::string::npos)
                                    domain = domain.substr(dotPos + 1);
                                else
                                    domain.clear();
                            }
                            if (!response)
                            {
                                response = CreateDnsResponseNS(transId, qname, {}, 0);
                            }
                        }
                    }

                    if (response)
                    {
                        socket->SendTo(response, 0, from);
                        NS_LOG_INFO("DNS Server: Sent response (" << response->GetSize() << " bytes)");
                    }
                }
            }
        }
    }

    Ptr<Socket> m_socket;
    uint16_t m_nextTransId;
    std::map<std::string, std::vector<std::string>> m_aRecords;
    std::map<std::string, std::vector<std::pair<std::string, std::string>>> m_nsRecords;
};

// =============================================================================
// DNS CLIENT APPLICATION
// =============================================================================
// Relevant to Basic DNS Queries: DnsClientApp sends queries to DNS server
// Relevant to Basic HTTP GET/Response: HTTP client uses DNS to resolve hostnames
// =============================================================================

class DnsClientApp : public Application
{
  public:
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("DnsClientApp")
                                .SetParent<Application>()
                                .SetGroupName("Tutorial")
                                .AddConstructor<DnsClientApp>();
        return tid;
    }

    DnsClientApp() : m_socket(nullptr), m_nextTransId(0x1234) {}
    ~DnsClientApp() override { m_socket = nullptr; }

    // Relevant to Basic DNS Queries: SetDnsServer configures destination IP for queries
    void SetDnsServer(Address addr) { m_dnsServer = addr; }

    typedef Callback<void, std::string, std::vector<std::string>> ResolveCallback;

    // =============================================================================
    // Relevant to Query Types: Resolve() selects DNS query type (A or NS)
    // Relevant to DNS Caching: Cache is checked before sending a query
    // Relevant to DNS and HTTP Interaction: Transaction ID is generated here
    // =============================================================================
    void Resolve(const std::string& hostname, uint16_t qtype, ResolveCallback callback)
    {
        // Relevant to DNS Caching: Check cache first (only for A records)
        // To disable caching, remove or bypass this lookup
        if (qtype == DNS_TYPE_A)
        {
            std::vector<std::string> cached;
            if (g_dnsCache.Lookup(hostname, cached))
            {
                // Cache hit - no DNS query sent
                // Relevant to DNS Caching: Cached entry reused until expiration
                callback(hostname, cached);
                return;
            }
        }

        // Relevant to DNS and HTTP Interaction: Generate unique transaction ID
        uint16_t transId = m_nextTransId++;
        m_pendingQueries[transId] = {hostname, qtype, callback};

        // Relevant to Query Types: Query type passed to CreateDnsQuery
        Ptr<Packet> query = CreateDnsQuery(transId, hostname, qtype);
        m_socket->Send(query);
        NS_LOG_INFO("DNS Client: Sent query for " << hostname << " type " << qtype
                    << " (ID: 0x" << std::hex << transId << std::dec << ")");
    }

  protected:
    void StartApplication() override
    {
        if (!m_socket)
        {
            m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
            m_socket->Bind();
            // Relevant to Basic DNS Queries: Connect to DNS server (port 53)
            m_socket->Connect(m_dnsServer);
        }
        m_socket->SetRecvCallback(MakeCallback(&DnsClientApp::HandleRead, this));
    }

    void StopApplication() override
    {
        if (m_socket)
        {
            m_socket->Close();
            m_socket->SetRecvCallback(MakeNullCallback<void, Ptr<Socket>>());
        }
    }

  private:
    // =============================================================================
    // Relevant to Basic DNS Queries: HandleRead processes DNS responses
    // Answers contain IP addresses for A records
    // =============================================================================
    void HandleRead(Ptr<Socket> socket)
    {
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom(from)))
        {
            if (packet->GetSize() >= 12)
            {
                uint8_t buf[512];
                uint32_t size = packet->CopyData(buf, sizeof(buf));

                uint16_t transId = (buf[0] << 8) | buf[1];
                uint16_t ancount = (buf[6] << 8) | buf[7];

                NS_LOG_INFO("DNS Client: Received response (ID: 0x" << std::hex << transId
                            << std::dec << ") with " << ancount << " answers");

                auto it = m_pendingQueries.find(transId);
                if (it != m_pendingQueries.end())
                {
                    std::vector<std::string> results;

                    // Parse answers (simplified - assumes A records)
                    // Skip header (12 bytes) and question section
                    size_t pos = 12;
                    // Skip question name
                    while (pos < size && buf[pos] != 0)
                    {
                        if ((buf[pos] & 0xC0) == 0xC0)
                        {
                            pos += 2;
                            break;
                        }
                        pos += buf[pos] + 1;
                    }
                    if (pos < size && buf[pos] == 0) pos++;
                    pos += 4; // skip qtype and qclass

                    // Relevant to Basic DNS Queries: Parse answer records
                    for (uint16_t i = 0; i < ancount && pos + 12 <= size; ++i)
                    {
                        // Skip name (pointer or labels)
                        if ((buf[pos] & 0xC0) == 0xC0)
                        {
                            pos += 2;
                        }
                        else
                        {
                            while (pos < size && buf[pos] != 0)
                                pos += buf[pos] + 1;
                            pos++;
                        }

                        uint16_t rtype = (buf[pos] << 8) | buf[pos + 1];
                        pos += 2;
                        pos += 2; // class
                        pos += 4; // ttl
                        uint16_t rdlength = (buf[pos] << 8) | buf[pos + 1];
                        pos += 2;

                        // Relevant to Basic DNS Queries: Extract IPv4 address from A record
                        if (rtype == DNS_TYPE_A && rdlength == 4 && pos + 4 <= size)
                        {
                            std::ostringstream oss;
                            oss << (int)buf[pos] << "." << (int)buf[pos + 1] << "."
                                << (int)buf[pos + 2] << "." << (int)buf[pos + 3];
                            results.push_back(oss.str());
                        }
                        pos += rdlength;
                    }

                    // Relevant to DNS Caching: Store response in cache with TTL
                    if (!results.empty() && it->second.qtype == DNS_TYPE_A)
                    {
                        g_dnsCache.Store(it->second.hostname, results, g_dnsTTL);
                    }

                    // Invoke callback directly
                    it->second.callback(it->second.hostname, results);
                    m_pendingQueries.erase(it);
                }
            }
        }
    }

    struct PendingQuery
    {
        std::string hostname;
        uint16_t qtype;
        ResolveCallback callback;
    };

    Ptr<Socket> m_socket;
    Address m_dnsServer;
    // Relevant to DNS and HTTP Interaction: m_nextTransId generates unique transaction IDs
    uint16_t m_nextTransId;
    std::map<uint16_t, PendingQuery> m_pendingQueries;
};

// =============================================================================
// HTTP SERVER APPLICATION
// =============================================================================
// Relevant to Conditional GET: Server stores Last-Modified timestamps
// Relevant to HTTP Authentication: Server verifies credentials
// =============================================================================

class HttpServerApp : public Application
{
  public:
    // Relevant to Conditional GET: ContentInfo stores Last-Modified for each resource
    struct ContentInfo
    {
        std::string body;
        std::string contentType;
        std::string lastModified;  // Used for conditional GET comparison
        bool requireAuth = false;
        std::string authRealm;
        std::string validCredentials;  // Base64-encoded credentials for Basic auth
    };

    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("HttpServerApp")
                                .SetParent<Application>()
                                .SetGroupName("Tutorial")
                                .AddConstructor<HttpServerApp>();
        return tid;
    }

    HttpServerApp() : m_socket(nullptr), m_requireAuth(false) {}
    ~HttpServerApp() override { m_socket = nullptr; }

    // Relevant to Long Document Retrieval: AddContent sets response payload size
    void AddContent(const std::string& path, const std::string& body,
                    const std::string& contentType = "text/html",
                    const std::string& lastModified = "")
    {
        ContentInfo info;
        info.body = body;
        info.contentType = contentType;
        info.lastModified = lastModified.empty() ? GetCurrentHttpDate() : lastModified;
        info.requireAuth = false;
        m_content[path] = info;
    }

    // Relevant to HTTP Authentication: AddProtectedContent requires valid credentials
    void AddProtectedContent(const std::string& path, const std::string& body,
                             const std::string& realm, const std::string& validCredentials,
                             const std::string& contentType = "text/html",
                             const std::string& lastModified = "")
    {
        ContentInfo info;
        info.body = body;
        info.contentType = contentType;
        info.lastModified = lastModified.empty() ? GetCurrentHttpDate() : lastModified;
        info.requireAuth = true;
        info.authRealm = realm;
        info.validCredentials = validCredentials;
        m_content[path] = info;
    }

    void SetRequireAuth(bool require, const std::string& realm = "Protected",
                        const std::string& validCredentials = "")
    {
        m_requireAuth = require;
        m_authRealm = realm;
        m_validCredentials = validCredentials;
    }

    void SetServerName(const std::string& name) { m_serverName = name; }

  protected:
    void StartApplication() override
    {
        if (!m_socket)
        {
            m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
            InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), 80);
            m_socket->Bind(local);
            m_socket->Listen();
        }
        m_socket->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&HttpServerApp::HandleAccept, this));
    }

    void StopApplication() override
    {
        if (m_socket)
        {
            m_socket->Close();
        }
        for (auto& s : m_clientSockets)
        {
            s->Close();
        }
        m_clientSockets.clear();
    }

  private:
    std::string GetCurrentHttpDate()
    {
        // Fixed date for reproducibility
        return "Mon, 27 Jan 2025 12:00:00 GMT";
    }

    void HandleAccept(Ptr<Socket> socket, const Address& from)
    {
        NS_LOG_INFO("HTTP Server [" << m_serverName << "]: Connection from "
                    << InetSocketAddress::ConvertFrom(from).GetIpv4());
        socket->SetRecvCallback(MakeCallback(&HttpServerApp::HandleRead, this));
        socket->SetCloseCallbacks(MakeCallback(&HttpServerApp::HandleClose, this),
                                  MakeCallback(&HttpServerApp::HandleClose, this));
        m_clientSockets.push_back(socket);
        m_clientBuffers[socket] = "";
    }

    void HandleClose(Ptr<Socket> socket)
    {
        m_clientBuffers.erase(socket);
        m_clientSockets.erase(
            std::remove(m_clientSockets.begin(), m_clientSockets.end(), socket),
            m_clientSockets.end());
    }

    void HandleRead(Ptr<Socket> socket)
    {
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom(from)))
        {
            if (packet->GetSize() > 0)
            {
                uint8_t buffer[4096];
                uint32_t size = packet->CopyData(buffer, sizeof(buffer) - 1);
                buffer[size] = '\0';

                m_clientBuffers[socket] += std::string(reinterpret_cast<char*>(buffer), size);

                // Check for complete request (ends with \r\n\r\n)
                if (m_clientBuffers[socket].find("\r\n\r\n") != std::string::npos)
                {
                    ProcessRequest(socket, m_clientBuffers[socket]);
                    m_clientBuffers[socket].clear();
                }
            }
        }
    }

    // =============================================================================
    // Relevant to Conditional GET: ProcessRequest checks If-Modified-Since header
    // Relevant to HTTP Authentication: ProcessRequest verifies Authorization header
    // =============================================================================
    void ProcessRequest(Ptr<Socket> socket, const std::string& request)
    {
        NS_LOG_INFO("HTTP Server [" << m_serverName << "]: Received request");

        // Parse request line
        std::istringstream iss(request);
        std::string method, path, version;
        iss >> method >> path >> version;

        // Parse headers
        std::map<std::string, std::string> headers;
        std::string line;
        std::getline(iss, line); // consume rest of first line
        while (std::getline(iss, line) && line != "\r" && !line.empty())
        {
            if (line.back() == '\r') line.pop_back();
            size_t colonPos = line.find(':');
            if (colonPos != std::string::npos)
            {
                std::string key = line.substr(0, colonPos);
                std::string value = line.substr(colonPos + 1);
                // Trim leading whitespace
                while (!value.empty() && value[0] == ' ') value.erase(0, 1);
                headers[key] = value;
            }
        }

        // Find content first
        auto contentIt = m_content.find(path);
        if (contentIt == m_content.end())
        {
            SendNotFound(socket, path);
            return;
        }

        // Relevant to HTTP Authentication: Check credentials if auth required
        bool needsAuth = contentIt->second.requireAuth || m_requireAuth;
        std::string realm = contentIt->second.requireAuth ? contentIt->second.authRealm : m_authRealm;
        std::string validCreds = contentIt->second.requireAuth ? contentIt->second.validCredentials : m_validCredentials;

        if (needsAuth)
        {
            // Relevant to HTTP Authentication: Server checks Authorization header value
            auto authIt = headers.find("Authorization");
            if (authIt == headers.end() || authIt->second != "Basic " + validCreds)
            {
                // No valid credentials - send 401 Unauthorized
                SendUnauthorizedWithRealm(socket, realm);
                return;
            }
        }

        // =============================================================================
        // Relevant to Conditional GET: Check If-Modified-Since for conditional GET
        // Server compares timestamps and returns 304 if not modified
        // =============================================================================
        auto imsIt = headers.find("If-Modified-Since");
        if (imsIt != headers.end())
        {
            // Relevant to Conditional GET: Compare If-Modified-Since with Last-Modified
            if (imsIt->second == contentIt->second.lastModified)
            {
                // Relevant to Conditional GET: 304 generated when times match
                SendNotModified(socket, contentIt->second.lastModified);
                return;
            }
        }

        // Send full response
        SendOK(socket, contentIt->second);
    }

    void SendOK(Ptr<Socket> socket, const ContentInfo& content)
    {
        std::ostringstream oss;
        oss << "HTTP/1.1 200 OK\r\n"
            << "Date: " << GetCurrentHttpDate() << "\r\n"
            << "Server: " << m_serverName << "\r\n"
            << "Last-Modified: " << content.lastModified << "\r\n"
            << "Content-Type: " << content.contentType << "\r\n"
            << "Content-Length: " << content.body.length() << "\r\n"
            << "Connection: close\r\n"
            << "\r\n"
            << content.body;

        std::string response = oss.str();
        Ptr<Packet> p = Create<Packet>((const uint8_t*)response.c_str(), response.length());
        socket->Send(p);
        NS_LOG_INFO("HTTP Server [" << m_serverName << "]: Sent 200 OK (" << response.length() << " bytes)");
        Simulator::Schedule(MilliSeconds(100), &Socket::Close, socket);
    }

    // =============================================================================
    // Relevant to Conditional GET: SendNotModified returns 304 with no body
    // =============================================================================
    void SendNotModified(Ptr<Socket> socket, const std::string& lastModified)
    {
        std::ostringstream oss;
        oss << "HTTP/1.1 304 Not Modified\r\n"
            << "Date: " << GetCurrentHttpDate() << "\r\n"
            << "Server: " << m_serverName << "\r\n"
            << "Last-Modified: " << lastModified << "\r\n"
            << "Connection: close\r\n"
            << "\r\n";  // No entity body for 304 response

        std::string response = oss.str();
        Ptr<Packet> p = Create<Packet>((const uint8_t*)response.c_str(), response.length());
        socket->Send(p);
        NS_LOG_INFO("HTTP Server [" << m_serverName << "]: Sent 304 Not Modified");
        Simulator::Schedule(MilliSeconds(100), &Socket::Close, socket);
    }

    void SendNotFound(Ptr<Socket> socket, const std::string& path)
    {
        std::string body = "<html><body><h1>404 Not Found</h1><p>" + path + " not found.</p></body></html>";
        std::ostringstream oss;
        oss << "HTTP/1.1 404 Not Found\r\n"
            << "Date: " << GetCurrentHttpDate() << "\r\n"
            << "Server: " << m_serverName << "\r\n"
            << "Content-Type: text/html\r\n"
            << "Content-Length: " << body.length() << "\r\n"
            << "Connection: close\r\n"
            << "\r\n"
            << body;

        std::string response = oss.str();
        Ptr<Packet> p = Create<Packet>((const uint8_t*)response.c_str(), response.length());
        socket->Send(p);
        NS_LOG_INFO("HTTP Server [" << m_serverName << "]: Sent 404 Not Found");
        Simulator::Schedule(MilliSeconds(100), &Socket::Close, socket);
    }

    void SendUnauthorized(Ptr<Socket> socket)
    {
        SendUnauthorizedWithRealm(socket, m_authRealm);
    }

    // =============================================================================
    // Relevant to HTTP Authentication: 401 Unauthorized with WWW-Authenticate header
    // =============================================================================
    void SendUnauthorizedWithRealm(Ptr<Socket> socket, const std::string& realm)
    {
        std::string body = "<html><body><h1>401 Unauthorized</h1>"
                           "<p>You must authenticate to access this resource.</p></body></html>";
        std::ostringstream oss;
        oss << "HTTP/1.1 401 Unauthorized\r\n"
            << "Date: " << GetCurrentHttpDate() << "\r\n"
            << "Server: " << m_serverName << "\r\n"
            << "WWW-Authenticate: Basic realm=\"" << realm << "\"\r\n"
            << "Content-Type: text/html\r\n"
            << "Content-Length: " << body.length() << "\r\n"
            << "Connection: close\r\n"
            << "\r\n"
            << body;

        std::string response = oss.str();
        Ptr<Packet> p = Create<Packet>((const uint8_t*)response.c_str(), response.length());
        socket->Send(p);
        NS_LOG_INFO("HTTP Server [" << m_serverName << "]: Sent 401 Unauthorized");
        Simulator::Schedule(MilliSeconds(100), &Socket::Close, socket);
    }

    Ptr<Socket> m_socket;
    std::vector<Ptr<Socket>> m_clientSockets;
    std::map<Ptr<Socket>, std::string> m_clientBuffers;
    std::map<std::string, ContentInfo> m_content;
    bool m_requireAuth;
    std::string m_authRealm;
    std::string m_validCredentials;
    std::string m_serverName = "ns3-http/1.0";
};

// =============================================================================
// HTTP CLIENT APPLICATION
// =============================================================================
// Relevant to Basic HTTP GET/Response: HttpClientApp constructs and sends HTTP requests
// Relevant to Embedded Objects: Client can fetch multiple objects from different servers
// =============================================================================

class HttpClientApp : public Application
{
  public:
    struct HttpRequest
    {
        std::string host;
        std::string path;
        std::string serverIp;
        std::string ifModifiedSince;  // For conditional GET
        std::string authorization;     // For HTTP Basic auth
    };

    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("HttpClientApp")
                                .SetParent<Application>()
                                .SetGroupName("Tutorial")
                                .AddConstructor<HttpClientApp>();
        return tid;
    }

    HttpClientApp() : m_dnsClient(nullptr) {}
    ~HttpClientApp() override {}

    void SetDnsClient(Ptr<DnsClientApp> dns) { m_dnsClient = dns; }

    // =============================================================================
    // Relevant to Basic HTTP GET/Response: FetchUrl initiates DNS resolution then HTTP
    // Relevant to Conditional GET: ifModifiedSince triggers cache validation
    // Relevant to HTTP Authentication: authorization header for protected resources
    // =============================================================================
    void FetchUrl(const std::string& host, const std::string& path,
                  const std::string& ifModifiedSince = "",
                  const std::string& authorization = "")
    {
        HttpRequest req;
        req.host = host;
        req.path = path;
        req.ifModifiedSince = ifModifiedSince;  // Relevant to Conditional GET
        req.authorization = authorization;       // Relevant to HTTP Authentication
        m_pendingRequests.push_back(req);

        // Relevant to Basic HTTP GET/Response: Resolve hostname via DNS before connecting
        m_dnsClient->Resolve(host, DNS_TYPE_A,
                             MakeCallback(&HttpClientApp::OnDnsResolved, this));
    }

    // Schedule multiple requests
    void ScheduleFetch(Time delay, const std::string& host, const std::string& path,
                       const std::string& ifModifiedSince = "",
                       const std::string& authorization = "")
    {
        Simulator::Schedule(delay, &HttpClientApp::FetchUrl, this,
                            host, path, ifModifiedSince, authorization);
    }

  protected:
    void StartApplication() override
    {
    }

    void StopApplication() override
    {
        for (auto& s : m_sockets)
        {
            if (s)
            {
                s->Close();
            }
        }
        m_sockets.clear();
    }

  private:
    // =============================================================================
    // Relevant to Basic HTTP GET/Response: OnDnsResolved creates TCP connection to server
    // Client uses resolved IP address to connect to HTTP server port 80
    // =============================================================================
    void OnDnsResolved(std::string hostname, std::vector<std::string> addresses)
    {
        if (addresses.empty())
        {
            NS_LOG_ERROR("HTTP Client: DNS resolution failed for " << hostname);
            return;
        }

        NS_LOG_INFO("HTTP Client: DNS resolved " << hostname << " to " << addresses[0]);

        // Find pending request for this host - search from the END (most recent first)
        // This ensures that when DNS is cached, we process the request that just triggered this callback
        bool found = false;
        for (auto it = m_pendingRequests.rbegin(); it != m_pendingRequests.rend(); ++it)
        {
            if (it->host == hostname)
            {
                found = true;

                // Relevant to Basic HTTP GET/Response: Create TCP socket to server
                Ptr<Socket> socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
                socket->Bind();
                socket->SetConnectCallback(
                    MakeCallback(&HttpClientApp::ConnectionSucceeded, this),
                    MakeCallback(&HttpClientApp::ConnectionFailed, this));
                socket->SetRecvCallback(MakeCallback(&HttpClientApp::HandleRead, this));

                HttpRequest req = *it;
                req.serverIp = addresses[0];
                m_socketRequests[socket] = req;
                m_sockets.push_back(socket);

                // Relevant to Basic HTTP GET/Response: Connect to resolved IP on port 80
                InetSocketAddress remote(Ipv4Address(addresses[0].c_str()), 80);
                socket->Connect(remote);

                // Convert reverse iterator to forward iterator for erase
                m_pendingRequests.erase(std::next(it).base());
                break;
            }
        }

        if (!found)
        {
            NS_LOG_WARN("HTTP Client: No pending request found for " << hostname);
        }
    }

    void ConnectionSucceeded(Ptr<Socket> socket)
    {
        auto it = m_socketRequests.find(socket);
        if (it != m_socketRequests.end())
        {
            SendHttpRequest(socket, it->second);
        }
    }

    void ConnectionFailed(Ptr<Socket> socket)
    {
        NS_LOG_ERROR("HTTP Client: Connection failed");
    }

    // =============================================================================
    // Relevant to Basic HTTP GET/Response: HTTP request line constructed here
    // Relevant to Basic HTTP GET/Response: Accept and Accept-Language headers set here
    // Relevant to Conditional GET: If-Modified-Since header added when cached
    // Relevant to HTTP Authentication: Authorization header added for protected resources
    // =============================================================================
    void SendHttpRequest(Ptr<Socket> socket, const HttpRequest& req)
    {
        std::ostringstream oss;
        // Relevant to Basic HTTP GET/Response: HTTP request line (method, path, version)
        oss << "GET " << req.path << " HTTP/1.1\r\n"
            << "Host: " << req.host << "\r\n"
            << "User-Agent: ns3-http-client/1.0 (Wireshark Lab)\r\n"
            // Relevant to Basic HTTP GET/Response: Accept header indicates acceptable content types
            << "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            // Relevant to Basic HTTP GET/Response: Accept-Language header indicates language preferences
            << "Accept-Language: en-US,en;q=0.5\r\n"
            << "Accept-Encoding: identity\r\n";

        // Relevant to Conditional GET: If-Modified-Since added when cache has Last-Modified
        if (!req.ifModifiedSince.empty())
        {
            oss << "If-Modified-Since: " << req.ifModifiedSince << "\r\n";
        }
        // Relevant to HTTP Authentication: Authorization header added after receiving 401
        if (!req.authorization.empty())
        {
            oss << "Authorization: " << req.authorization << "\r\n";
        }

        oss << "Connection: close\r\n"
            << "\r\n";

        std::string request = oss.str();
        Ptr<Packet> p = Create<Packet>((const uint8_t*)request.c_str(), request.length());
        socket->Send(p);

        NS_LOG_INFO("HTTP Client: Sent GET " << req.path << " to " << req.host);
    }

    void HandleRead(Ptr<Socket> socket)
    {
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom(from)))
        {
            if (packet->GetSize() > 0)
            {
                // Just log that we received data
                NS_LOG_INFO("HTTP Client: Received " << packet->GetSize() << " bytes");
            }
        }
    }

    Ptr<DnsClientApp> m_dnsClient;
    std::vector<Ptr<Socket>> m_sockets;
    std::list<HttpRequest> m_pendingRequests;
    std::map<Ptr<Socket>, HttpRequest> m_socketRequests;
};

// =============================================================================
// SCENARIO SETUP FUNCTIONS
// =============================================================================

// =============================================================================
// Relevant to Basic HTTP GET/Response: SetupBasicScenario configures single object fetch
// Only one TCP connection opened because single object with no embedded resources
// =============================================================================
void SetupBasicScenario(Ptr<HttpServerApp> server1, Ptr<HttpClientApp> client, Ptr<DnsClientApp> dnsClient)
{
    // Simple HTML file
    std::string htmlBody =
        "<!DOCTYPE html>\r\n"
        "<html>\r\n"
        "<head><title>Wireshark Lab File 1</title></head>\r\n"
        "<body>\r\n"
        "Congratulations! You have successfully downloaded the first Wireshark lab file!\r\n"
        "</body>\r\n"
        "</html>\r\n";

    server1->AddContent("/wireshark-labs/HTTP-wireshark-file1.html", htmlBody,
                        "text/html", "Mon, 27 Jan 2025 11:30:00 GMT");

    // Client fetches the page - single request
    client->ScheduleFetch(Seconds(1.0), "www.example.com",
                          "/wireshark-labs/HTTP-wireshark-file1.html");
}

// =============================================================================
// Relevant to Conditional GET: SetupConditionalScenario demonstrates cache validation
// First request gets full content, second sends If-Modified-Since and gets 304
// =============================================================================
void SetupConditionalScenario(Ptr<HttpServerApp> server1, Ptr<HttpClientApp> client, Ptr<DnsClientApp> dnsClient)
{
    // Five-line HTML file
    std::string htmlBody =
        "<!DOCTYPE html>\r\n"
        "<html>\r\n"
        "<head><title>Wireshark Lab File 2</title></head>\r\n"
        "<body>\r\n"
        "Line 1: This is a test file for conditional GET.\r\n"
        "Line 2: The server will return Last-Modified header.\r\n"
        "Line 3: On second request, client sends If-Modified-Since.\r\n"
        "Line 4: Server responds with 304 Not Modified.\r\n"
        "Line 5: No body is returned for 304 response.\r\n"
        "</body>\r\n"
        "</html>\r\n";

    // Relevant to Conditional GET: lastModified timestamp stored by server
    std::string lastModified = "Mon, 27 Jan 2025 11:00:00 GMT";
    server1->AddContent("/wireshark-labs/HTTP-wireshark-file2.html", htmlBody,
                        "text/html", lastModified);

    // First request - gets full content with Last-Modified header in response
    client->ScheduleFetch(Seconds(1.0), "www.example.com",
                          "/wireshark-labs/HTTP-wireshark-file2.html");

    // Relevant to Conditional GET: Second request sends If-Modified-Since (cache hit triggers this)
    // Should get 304 Not Modified because timestamp matches
    client->ScheduleFetch(Seconds(3.0), "www.example.com",
                          "/wireshark-labs/HTTP-wireshark-file2.html",
                          lastModified);  // If-Modified-Since header value
}

// =============================================================================
// Relevant to Long Document Retrieval: Large response spans multiple TCP segments
// TCP handles segmentation automatically - application doesn't explicitly segment
// =============================================================================
void SetupLongDocumentScenario(Ptr<HttpServerApp> server1, Ptr<HttpClientApp> client, Ptr<DnsClientApp> dnsClient)
{
    // Relevant to Long Document Retrieval: Create a long document (~5000 bytes)
    // Response size exceeds TCP MSS, causing multiple segments
    std::ostringstream oss;
    oss << "<!DOCTYPE html>\r\n"
        << "<html>\r\n"
        << "<head><title>The Bill of Rights</title></head>\r\n"
        << "<body>\r\n"
        << "<h1>The Bill of Rights</h1>\r\n"
        << "<h2>Amendments 1-10 of the Constitution</h2>\r\n\r\n";

    // Add substantial content to exceed MSS
    oss << "<h3>Amendment I</h3>\r\n"
        << "<p>Congress shall make no law respecting an establishment of religion, "
        << "or prohibiting the free exercise thereof; or abridging the freedom of speech, "
        << "or of the press; or the right of the people peaceably to assemble, "
        << "and to petition the Government for a redress of grievances.</p>\r\n\r\n";

    oss << "<h3>Amendment II</h3>\r\n"
        << "<p>A well regulated Militia, being necessary to the security of a free State, "
        << "the right of the people to keep and bear Arms, shall not be infringed.</p>\r\n\r\n";

    oss << "<h3>Amendment III</h3>\r\n"
        << "<p>No Soldier shall, in time of peace be quartered in any house, without the consent "
        << "of the Owner, nor in time of war, but in a manner to be prescribed by law.</p>\r\n\r\n";

    oss << "<h3>Amendment IV</h3>\r\n"
        << "<p>The right of the people to be secure in their persons, houses, papers, and effects, "
        << "against unreasonable searches and seizures, shall not be violated, and no Warrants shall issue, "
        << "but upon probable cause, supported by Oath or affirmation, and particularly describing "
        << "the place to be searched, and the persons or things to be seized.</p>\r\n\r\n";

    oss << "<h3>Amendment V</h3>\r\n"
        << "<p>No person shall be held to answer for a capital, or otherwise infamous crime, "
        << "unless on a presentment or indictment of a Grand Jury, except in cases arising in the land "
        << "or naval forces, or in the Militia, when in actual service in time of War or public danger; "
        << "nor shall any person be subject for the same offence to be twice put in jeopardy of life or limb; "
        << "nor shall be compelled in any criminal case to be a witness against himself, nor be deprived "
        << "of life, liberty, or property, without due process of law; nor shall private property "
        << "be taken for public use, without just compensation.</p>\r\n\r\n";

    oss << "<h3>Amendment VI</h3>\r\n"
        << "<p>In all criminal prosecutions, the accused shall enjoy the right to a speedy and public trial, "
        << "by an impartial jury of the State and district wherein the crime shall have been committed, "
        << "which district shall have been previously ascertained by law, and to be informed of the nature "
        << "and cause of the accusation; to be confronted with the witnesses against him; to have compulsory "
        << "process for obtaining witnesses in his favor, and to have the Assistance of Counsel for his defence.</p>\r\n\r\n";

    oss << "<h3>Amendment VII</h3>\r\n"
        << "<p>In Suits at common law, where the value in controversy shall exceed twenty dollars, "
        << "the right of trial by jury shall be preserved, and no fact tried by a jury, shall be otherwise "
        << "re-examined in any Court of the United States, than according to the rules of the common law.</p>\r\n\r\n";

    oss << "<h3>Amendment VIII</h3>\r\n"
        << "<p>Excessive bail shall not be required, nor excessive fines imposed, "
        << "nor cruel and unusual punishments inflicted.</p>\r\n\r\n";

    oss << "<h3>Amendment IX</h3>\r\n"
        << "<p>The enumeration in the Constitution, of certain rights, shall not be construed "
        << "to deny or disparage others retained by the people.</p>\r\n\r\n";

    oss << "<h3>Amendment X</h3>\r\n"
        << "<p>The powers not delegated to the United States by the Constitution, nor prohibited by it "
        << "to the States, are reserved to the States respectively, or to the people.</p>\r\n\r\n";

    oss << "</body>\r\n</html>\r\n";

    std::string htmlBody = oss.str();
    // Relevant to Long Document Retrieval: Response payload size configured here
    NS_LOG_INFO("Long document size: " << htmlBody.length() << " bytes");

    server1->AddContent("/wireshark-labs/HTTP-wireshark-file3.html", htmlBody,
                        "text/html", "Mon, 27 Jan 2025 10:00:00 GMT");

    client->ScheduleFetch(Seconds(1.0), "www.example.com",
                          "/wireshark-labs/HTTP-wireshark-file3.html");
}

// =============================================================================
// Relevant to Embedded Objects: Base HTML references objects from two servers
// Relevant to Embedded Objects: g_parallelDownload controls serial vs parallel fetching
// =============================================================================
void SetupEmbeddedScenario(Ptr<HttpServerApp> server1, Ptr<HttpServerApp> server2,
                            Ptr<HttpClientApp> client, Ptr<DnsClientApp> dnsClient)
{
    // Relevant to Embedded Objects: Embedded URLs defined in HTML content
    // Base HTML with embedded objects from two servers
    std::string htmlBody =
        "<!DOCTYPE html>\r\n"
        "<html>\r\n"
        "<head><title>Page with Embedded Objects</title></head>\r\n"
        "<body>\r\n"
        "<h1>Wireshark Lab - Embedded Objects</h1>\r\n"
        "<p>This page contains images from two different servers:</p>\r\n"
        "<img src=\"http://www.example.com/images/logo.png\" alt=\"Logo from Server 1\">\r\n"
        "<img src=\"http://www.images.example.com/images/cover.jpg\" alt=\"Cover from Server 2\">\r\n"
        "</body>\r\n"
        "</html>\r\n";

    server1->AddContent("/wireshark-labs/HTTP-wireshark-file4.html", htmlBody,
                        "text/html", "Mon, 27 Jan 2025 09:00:00 GMT");

    // Simulated PNG image (just binary-looking data)
    std::string pngData(2048, '\x89');  // PNG-like data
    pngData[0] = '\x89';
    pngData[1] = 'P';
    pngData[2] = 'N';
    pngData[3] = 'G';
    server1->AddContent("/images/logo.png", pngData, "image/png", "Mon, 27 Jan 2025 08:00:00 GMT");

    // Simulated JPEG image on server 2 (different IP address)
    std::string jpgData(3072, '\xFF');  // JPEG-like data
    jpgData[0] = '\xFF';
    jpgData[1] = '\xD8';
    jpgData[2] = '\xFF';
    server2->AddContent("/images/cover.jpg", jpgData, "image/jpeg", "Mon, 27 Jan 2025 07:00:00 GMT");

    // First: fetch base HTML
    client->ScheduleFetch(Seconds(1.0), "www.example.com",
                          "/wireshark-labs/HTTP-wireshark-file4.html");

    // Relevant to Embedded Objects: Client discovers embedded objects by parsing HTML
    // (In this simulation, requests are scheduled manually to simulate parsing)
    // Relevant to DNS Caching: DNS queries issued for embedded objects unless cached
    if (g_parallelDownload)
    {
        // Relevant to Embedded Objects: Parallel - multiple TCP sockets and concurrent requests
        client->ScheduleFetch(Seconds(2.5), "www.example.com", "/images/logo.png");
        client->ScheduleFetch(Seconds(2.5), "www.images.example.com", "/images/cover.jpg");
    }
    else
    {
        // Relevant to Embedded Objects: Serial - one after another (default)
        client->ScheduleFetch(Seconds(2.5), "www.example.com", "/images/logo.png");
        client->ScheduleFetch(Seconds(4.0), "www.images.example.com", "/images/cover.jpg");
    }
}

// =============================================================================
// Relevant to HTTP Authentication: First request without auth gets 401
// Second request includes Authorization header and succeeds
// =============================================================================
void SetupAuthScenario(Ptr<HttpServerApp> server1, Ptr<HttpClientApp> client, Ptr<DnsClientApp> dnsClient)
{
    // Protected content
    std::string htmlBody =
        "<!DOCTYPE html>\r\n"
        "<html>\r\n"
        "<head><title>Protected Page</title></head>\r\n"
        "<body>\r\n"
        "<h1>Welcome, authenticated user!</h1>\r\n"
        "<p>You have successfully authenticated using HTTP Basic Authentication.</p>\r\n"
        "<p>Username: wireshark-students</p>\r\n"
        "</body>\r\n"
        "</html>\r\n";

    // Relevant to HTTP Authentication: Base64 encodes credentials per RFC 7617
    // username:password = wireshark-students:network
    std::string credentials = Base64Encode("wireshark-students:network");

    server1->AddContent("/protected_pages/HTTP-wireshark-file5.html", htmlBody,
                        "text/html", "Mon, 27 Jan 2025 06:00:00 GMT");
    server1->SetRequireAuth(true, "Protected Area", credentials);

    // First request without auth - should get 401
    client->ScheduleFetch(Seconds(1.0), "www.example.com",
                          "/protected_pages/HTTP-wireshark-file5.html");

    // Relevant to HTTP Authentication: Second request adds Authorization header after 401
    client->ScheduleFetch(Seconds(3.0), "www.example.com",
                          "/protected_pages/HTTP-wireshark-file5.html",
                          "",  // No If-Modified-Since
                          "Basic " + credentials);  // Authorization header
}

// Static callback function for DNS resolution results
static void OnDnsResult(std::string host, std::vector<std::string> addrs)
{
    if (addrs.empty())
    {
        NS_LOG_INFO("DNS Result: " << host << " resolved to NXDOMAIN");
    }
    else
    {
        NS_LOG_INFO("DNS Result: " << host << " resolved to " << addrs[0]);
    }
}

// Helper function to perform DNS resolve
static void DoDnsResolve(Ptr<DnsClientApp> dnsClient, std::string hostname, uint16_t qtype)
{
    dnsClient->Resolve(hostname, qtype, MakeCallback(&OnDnsResult));
}

// =============================================================================
// Relevant to Basic DNS Queries: SetupDnsScenario demonstrates DNS query types
// Relevant to DNS Caching: Repeated query for same hostname shows cache behavior
// =============================================================================
void SetupDnsScenario(Ptr<DnsClientApp> dnsClient)
{
    // Various DNS queries to demonstrate DNS lab concepts

    // Relevant to Query Types: Type A query for IPv4 address
    Simulator::Schedule(Seconds(1.0), &DoDnsResolve, dnsClient,
                        std::string("www.ietf.org"), DNS_TYPE_A);

    // Another Type A query
    Simulator::Schedule(Seconds(2.0), &DoDnsResolve, dnsClient,
                        std::string("www.mit.edu"), DNS_TYPE_A);

    // Relevant to Query Types: Type NS query for nameservers
    Simulator::Schedule(Seconds(3.0), &DoDnsResolve, dnsClient,
                        std::string("mit.edu"), DNS_TYPE_NS);

    // Relevant to DNS Caching: Cached query - should hit cache (no new DNS query sent)
    Simulator::Schedule(Seconds(4.0), &DoDnsResolve, dnsClient,
                        std::string("www.mit.edu"), DNS_TYPE_A);
}

// =============================================================================
// MAIN
// =============================================================================

int main(int argc, char* argv[])
{
    std::string scenario = "all";
    bool verbose = true;

    CommandLine cmd(__FILE__);
    cmd.AddValue("scenario", "Scenario: basic, conditional, long, embedded, auth, dns, all", scenario);
    cmd.AddValue("verbose", "Enable verbose logging", verbose);
    // Relevant to Embedded Objects: --parallel controls serial vs parallel downloads
    cmd.AddValue("parallel", "Parallel download for embedded scenario", g_parallelDownload);
    // Relevant to DNS Caching: --dnsTTL controls cache expiration
    cmd.AddValue("dnsTTL", "DNS cache TTL in seconds", g_dnsTTL);
    // Relevant to Long Document Retrieval: --mss affects TCP segmentation
    cmd.AddValue("mss", "TCP MSS for testing", g_tcpMss);
    cmd.Parse(argc, argv);

    if (verbose)
    {
        LogComponentEnable("WiresharkLab", LOG_LEVEL_INFO);
    }

    // Create output directory (note: contains space)
    std::filesystem::create_directories(outputDir);
    NS_LOG_INFO("Output directory: " << outputDir);
    NS_LOG_INFO("Scenario: " << scenario);

    // =========================================================================
    // Create topology
    // =========================================================================
    NodeContainer nodes;
    nodes.Create(4);
    // n0 = Client
    // n1 = DNS Server
    // n2 = HTTP Server 1 (www.example.com)
    // n3 = HTTP Server 2 (www.images.example.com)

    // CSMA network (Ethernet-like for proper Wireshark analysis)
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("100Mbps"));
    csma.SetChannelAttribute("Delay", TimeValue(NanoSeconds(6560)));

    NetDeviceContainer devices = csma.Install(nodes);

    // Set smaller MTU to force TCP segmentation for long documents
    for (uint32_t i = 0; i < devices.GetN(); ++i)
    {
        devices.Get(i)->SetMtu(1500);
    }

    // Install Internet stack
    InternetStackHelper internet;
    internet.Install(nodes);

    // Assign IP addresses
    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    // IP assignments:
    // n0 (Client):      10.1.1.1
    // n1 (DNS Server):  10.1.1.2
    // n2 (HTTP Server1): 10.1.1.3
    // n3 (HTTP Server2): 10.1.1.4

    NS_LOG_INFO("Client:        " << interfaces.GetAddress(0));
    NS_LOG_INFO("DNS Server:    " << interfaces.GetAddress(1));
    NS_LOG_INFO("HTTP Server 1: " << interfaces.GetAddress(2));
    NS_LOG_INFO("HTTP Server 2: " << interfaces.GetAddress(3));

    // =========================================================================
    // Create applications
    // =========================================================================

    // Relevant to Basic DNS Queries: DNS Server configured with A and NS records
    Ptr<DnsServerApp> dnsServer = CreateObject<DnsServerApp>();
    // Add DNS records
    // Relevant to Embedded Objects: www.example.com and www.images.example.com resolve to different IPs
    dnsServer->AddARecord("www.example.com", {"10.1.1.3"});
    dnsServer->AddARecord("www.images.example.com", {"10.1.1.4"});
    dnsServer->AddARecord("www.ietf.org", {"4.31.198.44"});
    // Relevant to Basic DNS Queries: Multiple A records can be returned
    dnsServer->AddARecord("www.mit.edu", {"23.66.210.137", "23.66.210.128"});
    // Relevant to DNS and HTTP Interaction: NS records return multiple nameservers
    dnsServer->AddNSRecord("mit.edu", {
        {"bitsy.mit.edu", "18.72.0.3"},
        {"strawb.mit.edu", "18.71.0.151"},
        {"w20ns.mit.edu", "18.70.0.160"}
    });
    dnsServer->AddNSRecord("example.com", {
        {"ns1.example.com", "10.1.1.2"},
        {"ns2.example.com", "10.1.1.2"}
    });
    nodes.Get(1)->AddApplication(dnsServer);
    dnsServer->SetStartTime(Seconds(0.0));
    dnsServer->SetStopTime(Seconds(30.0));

    // Relevant to Basic DNS Queries: DNS Client configured to query DNS server at 10.1.1.2:53
    Ptr<DnsClientApp> dnsClient = CreateObject<DnsClientApp>();
    dnsClient->SetDnsServer(InetSocketAddress(interfaces.GetAddress(1), 53));
    nodes.Get(0)->AddApplication(dnsClient);
    dnsClient->SetStartTime(Seconds(0.1));
    dnsClient->SetStopTime(Seconds(30.0));

    // HTTP Server 1 (www.example.com)
    Ptr<HttpServerApp> httpServer1 = CreateObject<HttpServerApp>();
    httpServer1->SetServerName("Apache/2.2.3 (CentOS)");
    nodes.Get(2)->AddApplication(httpServer1);
    httpServer1->SetStartTime(Seconds(0.0));
    httpServer1->SetStopTime(Seconds(30.0));

    // HTTP Server 2 (www.images.example.com)
    Ptr<HttpServerApp> httpServer2 = CreateObject<HttpServerApp>();
    httpServer2->SetServerName("nginx/1.18.0");
    nodes.Get(3)->AddApplication(httpServer2);
    httpServer2->SetStartTime(Seconds(0.0));
    httpServer2->SetStopTime(Seconds(30.0));

    // HTTP Client
    Ptr<HttpClientApp> httpClient = CreateObject<HttpClientApp>();
    httpClient->SetDnsClient(dnsClient);
    nodes.Get(0)->AddApplication(httpClient);
    httpClient->SetStartTime(Seconds(0.5));
    httpClient->SetStopTime(Seconds(30.0));

    // =========================================================================
    // Setup scenarios
    // =========================================================================

    if (scenario == "basic" || scenario == "all")
    {
        SetupBasicScenario(httpServer1, httpClient, dnsClient);
    }

    if (scenario == "conditional" || scenario == "all")
    {
        SetupConditionalScenario(httpServer1, httpClient, dnsClient);
    }

    if (scenario == "long" || scenario == "all")
    {
        SetupLongDocumentScenario(httpServer1, httpClient, dnsClient);
    }

    if (scenario == "embedded" || scenario == "all")
    {
        SetupEmbeddedScenario(httpServer1, httpServer2, httpClient, dnsClient);
    }

    if (scenario == "auth" || scenario == "all")
    {
        // Use per-path authentication for protected content
        std::string credentials = Base64Encode("wireshark-students:network");
        std::string htmlBody =
            "<!DOCTYPE html>\r\n"
            "<html>\r\n"
            "<head><title>Protected Page</title></head>\r\n"
            "<body>\r\n"
            "<h1>Welcome, authenticated user!</h1>\r\n"
            "<p>You have successfully authenticated using HTTP Basic Authentication.</p>\r\n"
            "<p>Username: wireshark-students</p>\r\n"
            "</body>\r\n"
            "</html>\r\n";

        // Add protected content to httpServer1 with per-path auth
        httpServer1->AddProtectedContent("/protected_pages/HTTP-wireshark-file5.html",
                                         htmlBody, "Protected Area", credentials,
                                         "text/html", "Mon, 27 Jan 2025 06:00:00 GMT");

        // Schedule requests at different times depending on scenario
        double baseTime = (scenario == "all") ? 7.0 : 1.0;

        // First request without auth - should get 401
        httpClient->ScheduleFetch(Seconds(baseTime), "www.example.com",
                                  "/protected_pages/HTTP-wireshark-file5.html");

        // Second request with auth - should get 200
        httpClient->ScheduleFetch(Seconds(baseTime + 2.0), "www.example.com",
                                  "/protected_pages/HTTP-wireshark-file5.html",
                                  "",  // No If-Modified-Since
                                  "Basic " + credentials);
    }

    if (scenario == "dns" || scenario == "all")
    {
        SetupDnsScenario(dnsClient);
    }

    // =========================================================================
    // Enable PCAP tracing
    // =========================================================================

    // Promiscuous capture on client - main analysis point
    csma.EnablePcap(outputDir + "client", devices.Get(0), true);

    // DNS server capture
    csma.EnablePcap(outputDir + "dns-server", devices.Get(1), true);

    // HTTP servers
    csma.EnablePcap(outputDir + "http-server1", devices.Get(2), true);
    csma.EnablePcap(outputDir + "http-server2", devices.Get(3), true);

    // All nodes
    csma.EnablePcapAll(outputDir + "all", true);

    // =========================================================================
    // Run simulation
    // =========================================================================

    NS_LOG_INFO("Starting simulation...");
    Simulator::Stop(Seconds(35.0));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("=== Simulation Complete ===");
    NS_LOG_INFO("PCAP files written to: " << outputDir);
    NS_LOG_INFO("Open with Wireshark and filter by 'http' or 'dns' to analyze traffic.");

    return 0;
}
