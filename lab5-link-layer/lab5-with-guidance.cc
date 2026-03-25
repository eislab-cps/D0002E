/*
 * =============================================================================
 * ns-3 Wireshark Lab Simulation - Link Layer and LANs
 * Extended version with seed-based randomization, NetAnim support,
 * and parameterized experiments.
 * =============================================================================
 *
 * Changes vs lab5-with-guidance.cc:
 *   - --seed <1..100>   Reproducible runs; same seed = identical output (default 100)
 *   - PCAP always ON by default (--pcap=0 to disable); no more --pcap=1 needed
 *   - NetAnim XML produced per scenario with full packet metadata
 *   - MobilityHelper sets node positions per topology so NetAnim is readable
 *   - PacketMetadata::Enable() called once so every arrow carries header info
 *   - Output placed under seed<N>/ subfolder to keep runs separate
 *   - jitter (0..0.095 s, derived from seed) shifts application start times
 *   - --errorRate <0..1>  CRC/frame error rate for the crc scenario (default 0.10)
 *
 * =============================================================================
 * HOW TO RUN EACH SCENARIO
 * =============================================================================
 *
 * Build:
 *   ./ns3 build scratch/d0002e/lab5-with-guidance
 *
 * Run scenarios (outputs go to "scratch/d0002e/lab 5 output/seed<N>/"):
 *
 * 1) ETHERNET BASIC:
 *    ./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=ethernet-basic"
 *    ./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=ethernet-basic --seed=42"
 *
 * 2) ARP:
 *    ./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=arp"
 *
 * 3) SWITCH LEARNING:
 *    ./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=switch-learning"
 *
 * 4) CRC (frame error detection):
 *    ./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=crc"
 *    ./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=crc --errorRate=0.05"
 *    ./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=crc --errorRate=0.30"
 *
 * 5) VLAN:
 *    ./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=vlan"
 *
 * 6) ALL SCENARIOS:
 *    ./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=all"
 *    ./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=all --seed=42"
 *
 * Additional flags:
 *   --pcap=0          Disable PCAP capture (default: enabled)
 *   --verbose=1       Enable ns-3 INFO-level logging
 *   --seed=100        RNG seed 1-100 (default: 100)
 *   --errorRate=0.10  CRC error rate 0..1 (default: 0.10, crc scenario only)
 *
 * =============================================================================
 * NETWORK TOPOLOGY OVERVIEW
 * =============================================================================
 *
 * ETHERNET-BASIC and ARP (4-node shared CSMA LAN):
 *
 *   n0 (10.1.1.1) ----+
 *   n1 (10.1.1.2) ----+--- Shared CSMA LAN (100 Mbps, 2 ms)
 *   n2 (10.1.1.3) ----+
 *   n3 (10.1.1.4) ----+
 *
 * SWITCH-LEARNING (star via bridge):
 *
 *   n0 ---[link0]---[port0]--+
 *   n1 ---[link1]---[port1]--+--- Bridge/Switch (no IP, layer-2 only)
 *   n2 ---[link2]---[port2]--+
 *   n3 ---[link3]---[port3]--+
 *
 * CRC (2-node CSMA with error model on n1):
 *
 *   n0 (10.1.4.1) ---- shared CSMA ---- n1 (10.1.4.2)
 *                                           ^ RateErrorModel
 *
 * VLAN (4-node shared CSMA, raw layer-2 frames):
 *
 *   n0 (VLAN 10) ----+
 *   n1 (VLAN 10) ----+--- Shared CSMA LAN (EtherType=0x8100)
 *   n2 (VLAN 20) ----+
 *   n3 (VLAN 20) ----+
 *
 * =============================================================================
 * QUESTIONS REFERENCE
 * =============================================================================
 *
 * [C] = Simulation code question  – answered by reading THIS script
 * [W] = Wireshark question        – answered by analysing PCAP files
 * [B] = Both code AND Wireshark   – requires both
 * [V] = Wireshark + textbook      – verify in Wireshark, explain with book
 *
 * =============================================================================
 */

#include "ns3/applications-module.h"
#include "ns3/bridge-module.h"
#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-apps-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"   // [NEW] ConstantPositionMobilityModel
#include "ns3/netanim-module.h"    // [NEW] AnimationInterface
#include "ns3/network-module.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("LinkLayerLab");

// =============================================================================
// OUTPUT DIRECTORY
// =============================================================================
static const std::string g_baseDir = "scratch/d0002e/lab 5 output/";

// =============================================================================
// PORT CONFIGURATION  –  IMPORTANT: avoid port 9 (DISCARD)
// =============================================================================
// GUIDANCE for [C]: DATA_PORT = 4000. UDP port 9 is the DISCARD service
// (RFC 863); Wireshark shows "DISCARD" for port 9, which is confusing.
// =============================================================================
static const uint16_t DATA_PORT = 4000;

// =============================================================================
// [NEW] PCAP default ON. Pass --pcap=0 to disable.
// =============================================================================
static bool g_pcapEnabled = true;

// =============================================================================
// [NEW] Seed parameter for reproducible randomization (range 1-100, default 100)
// =============================================================================
static uint32_t g_seed = 100;

// =============================================================================
// [NEW] CRC error rate for the crc scenario (default 0.10 = 10%)
// =============================================================================
static double g_errorRate = 0.10;

// =============================================================================
// HELPER: Create output directory (and parents)
// =============================================================================
static void
EnsureDirectory(const std::string& path)
{
    std::error_code ec;
    std::filesystem::create_directories(path, ec);
    if (ec)
        std::cerr << "WARNING: could not create directory: " << path
                  << "  (" << ec.message() << ")" << std::endl;
}

// =============================================================================
// HELPER: Verify PCAP file exists and is non-empty
// =============================================================================
static bool
VerifyPcapFile(const std::string& filepath)
{
    std::error_code ec;
    if (!std::filesystem::exists(filepath, ec))
    {
        std::cerr << "  MISSING PCAP: " << filepath << std::endl;
        return false;
    }
    auto sz = std::filesystem::file_size(filepath, ec);
    if (ec || sz == 0)
    {
        std::cerr << "  EMPTY PCAP: " << filepath << std::endl;
        return false;
    }
    std::cout << "  OK: " << filepath << "  (" << sz << " bytes)" << std::endl;
    return true;
}

// =============================================================================
// HELPER: Find first *.pcap in a directory and verify it is non-empty
// =============================================================================
static bool
VerifyAnyPcapInDir(const std::string& dirPath)
{
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(dirPath, ec))
    {
        if (entry.path().extension() == ".pcap")
            return VerifyPcapFile(entry.path().string());
    }
    std::cerr << "  NO PCAP FILES FOUND in " << dirPath << std::endl;
    return false;
}

// =============================================================================
// HELPER: Print IP/MAC address table for a set of nodes
// =============================================================================
// GUIDANCE for [C]: MAC addresses are assigned by CsmaHelper::Install()
// (sequential from 00:00:00:00:00:01). IP addresses are assigned by
// Ipv4AddressHelper::Assign().
// =============================================================================
static void
PrintAddressTable(const std::string& label,
                  NodeContainer nodes,
                  NetDeviceContainer devs,
                  Ipv4InterfaceContainer ifaces)
{
    std::cout << "\n  [" << label << "] Node address table:" << std::endl;
    std::cout << "  Node | IP Address      | MAC Address         | DevIfIndex" << std::endl;
    std::cout << "  -----|-----------------|---------------------|----------" << std::endl;
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        Ptr<NetDevice> dev = devs.Get(i);
        Mac48Address mac   = Mac48Address::ConvertFrom(dev->GetAddress());
        Ipv4Address   ip   = ifaces.GetAddress(i);
        std::cout << "  n" << nodes.Get(i)->GetId()
                  << "   | " << ip
                  << "      | " << mac
                  << "  | " << dev->GetIfIndex()
                  << std::endl;
    }
    std::cout << std::endl;
}

// =============================================================================
// HELPER: Expected PCAP filename for a given device
// =============================================================================
static std::string
PcapFilename(const std::string& prefix, Ptr<NetDevice> dev)
{
    std::ostringstream oss;
    oss << prefix << "-" << dev->GetNode()->GetId()
        << "-" << dev->GetIfIndex() << ".pcap";
    return oss.str();
}

// =============================================================================
// [NEW] SetupMobility: install ConstantPositionMobilityModel on every node.
// AnimationInterface reads positions from the mobility model; without this
// all nodes appear stacked at (0,0) in NetAnim.
// =============================================================================
static void
SetupMobility(NodeContainer& nodes,
              const std::vector<std::pair<double,double>>& positions)
{
    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    Ptr<ListPositionAllocator> alloc = CreateObject<ListPositionAllocator>();
    for (auto& p : positions)
        alloc->Add(Vector(p.first, p.second, 0.0));
    mobility.SetPositionAllocator(alloc);
    mobility.Install(nodes);
}

// =============================================================================
// [NEW] SetupNetAnim: common NetAnim configuration for IP-stack scenarios.
// Enables packet metadata and IPv4 counters, sets labels, colors, and sizes.
// Do NOT call for scenarios without an IP stack (switch bridge node, VLAN).
// =============================================================================
static void
SetupNetAnim(AnimationInterface& anim,
             NodeContainer& nodes,
             const std::vector<std::string>& labels,
             const std::vector<std::tuple<uint8_t,uint8_t,uint8_t>>& colors,
             double stopTime)
{
    anim.EnablePacketMetadata(true);
    anim.EnableIpv4L3ProtocolCounters(Seconds(0), Seconds(stopTime), Seconds(0.5));
    for (uint32_t i = 0; i < nodes.GetN() && i < labels.size(); ++i)
    {
        anim.UpdateNodeDescription(nodes.Get(i), labels[i]);
        if (i < colors.size())
        {
            auto [r, g, b] = colors[i];
            anim.UpdateNodeColor(nodes.Get(i), r, g, b);
        }
        anim.UpdateNodeSize(nodes.Get(i)->GetId(), 3.0, 3.0);
    }
}

// =============================================================================
// =============================================================================
// VLAN TAG HEADER  (802.1Q)
// =============================================================================
// =============================================================================
//
// GUIDANCE for [C]/[W]/[B] questions (VLAN scenario):
//
// 802.1Q inserts a 4-byte tag between the Ethernet src MAC and EtherType:
//
//  Byte 0-5:  Destination MAC
//  Byte 6-11: Source MAC
//  Byte 12-13: TPID = 0x8100  ← signals 802.1Q frame
//  Byte 14-15: TCI  = PCP(3b) | DEI(1b) | VID(12b)
//  Byte 16-17: Inner EtherType (e.g. 0x0800 for IPv4)
//  Byte 18+:  Inner payload
//
// Wireshark fields to inspect:
//   eth.type       → should be 0x8100
//   vlan.id        → VLAN ID (10 or 20)
//   vlan.priority  → Priority Code Point
//   vlan.etype     → Inner EtherType (0x0800)
// =============================================================================
class VlanTag : public Header
{
  public:
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::VlanTag")
                                .SetParent<Header>()
                                .AddConstructor<VlanTag>();
        return tid;
    }

    VlanTag() : m_tci(0), m_innerType(0x0800) {}

    void SetVlanId(uint16_t vid)    { m_tci = (m_tci & 0xF000) | (vid & 0x0FFF); }
    void SetPcp(uint8_t pcp)        { m_tci = (m_tci & 0x1FFF) | ((uint16_t)(pcp & 0x07) << 13); }
    void SetInnerType(uint16_t t)   { m_innerType = t; }
    uint16_t GetVlanId() const      { return m_tci & 0x0FFF; }

    TypeId GetInstanceTypeId() const override { return GetTypeId(); }

    void Print(std::ostream& os) const override
    {
        os << "VlanTag: VID=" << GetVlanId()
           << " InnerType=0x" << std::hex << m_innerType << std::dec;
    }

    uint32_t GetSerializedSize() const override { return 4; }

    void Serialize(Buffer::Iterator start) const override
    {
        start.WriteHtonU16(m_tci);
        start.WriteHtonU16(m_innerType);
    }

    uint32_t Deserialize(Buffer::Iterator start) override
    {
        m_tci       = start.ReadNtohU16();
        m_innerType = start.ReadNtohU16();
        return 4;
    }

  private:
    uint16_t m_tci;
    uint16_t m_innerType;
};

// =============================================================================
// VLAN SENDER APPLICATION
// =============================================================================
// GUIDANCE for [C]: VlanSenderApp uses a PacketSocket (raw layer-2 socket)
// with protocol=0x8100. CsmaNetDevice (DIX mode) places that protocol number
// into the Ethernet EtherType field → Wireshark sees EtherType=0x8100.
// VlanTag (4 bytes) is prepended as the first bytes of the payload:
//   bytes 0-1: TCI  (Priority|DEI|VLAN ID)
//   bytes 2-3: Inner EtherType
// =============================================================================
class VlanSenderApp : public Application
{
  public:
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::VlanSenderApp")
                                .SetParent<Application>()
                                .AddConstructor<VlanSenderApp>();
        return tid;
    }

    VlanSenderApp()
        : m_socket(nullptr), m_vlanId(10), m_devIfIndex(0),
          m_payloadSize(48), m_running(false), m_pktCount(0) {}

    virtual ~VlanSenderApp() { m_socket = nullptr; }

    void Setup(uint32_t devIfIndex, Mac48Address dest, uint16_t vlanId, uint32_t payloadSize = 48)
    {
        m_devIfIndex  = devIfIndex;
        m_dest        = dest;
        m_vlanId      = vlanId;
        m_payloadSize = payloadSize;
    }

  private:
    void StartApplication() override
    {
        m_running = true;
        m_socket  = Socket::CreateSocket(GetNode(), PacketSocketFactory::GetTypeId());

        PacketSocketAddress sockAddr;
        sockAddr.SetSingleDevice(m_devIfIndex);
        sockAddr.SetPhysicalAddress(m_dest);
        sockAddr.SetProtocol(0x8100); // 802.1Q TPID → sets EtherType in frame

        m_socket->Bind();
        m_socket->Connect(sockAddr);
        SendVlanFrame();
    }

    void StopApplication() override
    {
        m_running = false;
        if (m_socket) m_socket->Close();
    }

    void SendVlanFrame()
    {
        if (!m_running) return;

        Ptr<Packet> pkt = Create<Packet>(m_payloadSize);

        VlanTag vTag;
        vTag.SetVlanId(m_vlanId);
        vTag.SetInnerType(0x0800);
        pkt->AddHeader(vTag);

        m_socket->Send(pkt);
        m_pktCount++;

        std::cout << "    VLAN " << m_vlanId
                  << " frame #" << m_pktCount
                  << " sent from node " << GetNode()->GetId() << std::endl;

        if (m_running)
            Simulator::Schedule(Seconds(1.0), &VlanSenderApp::SendVlanFrame, this);
    }

    Ptr<Socket>  m_socket;
    uint16_t     m_vlanId;
    uint32_t     m_devIfIndex;
    Mac48Address m_dest;
    uint32_t     m_payloadSize;
    bool         m_running;
    uint32_t     m_pktCount;
};

// =============================================================================
// =============================================================================
// SCENARIO 1: ETHERNET BASIC
// =============================================================================
// =============================================================================
//
// PURPOSE: Show the structure of an Ethernet II frame in Wireshark.
// TOPOLOGY: 4 nodes on a single shared CSMA LAN (10.1.1.0/24).
// TRAFFIC: ICMP Echo (Ping) from n0 to n3.
//   - First packet triggers ARP (shows ARP before IP)
//   - Subsequent packets show Ethernet II + IPv4 + ICMP
//
// GUIDANCE for [C]:
//   Source MAC comes from the CsmaNetDevice installed by CsmaHelper::Install().
//   ns-3 auto-assigns sequential MACs starting at 00:00:00:00:00:01.
//   PingHelper creates ICMP Echo; IP layer wraps in IPv4 (EtherType=0x0800).
//   ARP uses EtherType=0x0806. 802.1Q VLAN uses EtherType=0x8100.
//
// GUIDANCE for [W]:
//   Open any PCAP. Expand "Ethernet II" header tree.
//   Fields: Source, Destination, Type (0x0800).
//   Filter "eth" → all Ethernet;  "icmp" → ICMP only.
//   frame.len → total frame length in bytes.
//
// GUIDANCE for [V]:
//   Minimum Ethernet payload = 46 bytes (to reach 64-byte minimum frame).
//   64 bytes = 6 dst + 6 src + 2 EtherType + 46 payload + 4 FCS.
// =============================================================================
static void
RunEthernetBasic(const std::string& outDir, const std::string& animFile, double jitter)
{
    std::cout << "\n========================================" << std::endl;
    std::cout << "SCENARIO: ethernet-basic" << std::endl;
    std::cout << "Seed: " << g_seed << "  (jitter=" << jitter << "s)" << std::endl;
    std::cout << "Output:   " << outDir << std::endl;
    std::cout << "========================================" << std::endl;

    EnsureDirectory(outDir);

    NodeContainer nodes;
    nodes.Create(4);

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", DataRateValue(DataRate("100Mbps")));
    csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));
    NetDeviceContainer devices = csma.Install(nodes);

    // [NEW] Horizontal chain layout for NetAnim
    SetupMobility(nodes, {{10,50},{30,50},{70,50},{90,50}});

    InternetStackHelper internet;
    internet.SetIpv6StackInstall(false);
    internet.Install(nodes);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer ifaces = ipv4.Assign(devices);

    PrintAddressTable("ethernet-basic", nodes, devices, ifaces);

    // =========================================================================
    // GUIDANCE for [C]/[B]: PingHelper installs ICMP Echo on n0 → n3.
    // First ping triggers ARP Request (dst=ff:ff:ff:ff:ff:ff).
    // ARP Reply unicasts n3's MAC back to n0.
    // [NEW] jitter shifts start time so seeds produce distinguishable timestamps.
    // =========================================================================
    PingHelper ping(ifaces.GetAddress(3));
    ping.SetAttribute("Interval", TimeValue(Seconds(1.0)));
    ping.SetAttribute("Size", UintegerValue(56));
    ApplicationContainer pingApp = ping.Install(nodes.Get(0));
    pingApp.Start(Seconds(1.0 + jitter));
    pingApp.Stop(Seconds(8.0));

    // =========================================================================
    // GUIDANCE for [W]: Capture on ALL nodes in promiscuous mode.
    // All frames on the shared Ethernet bus are visible on every node.
    // Wireshark key fields: eth.src, eth.dst, eth.type, frame.len
    // =========================================================================
    if (g_pcapEnabled)
    {
        std::string prefix = outDir + "eth-basic";
        csma.EnablePcap(prefix, devices, true);
        for (uint32_t i = 0; i < devices.GetN(); i++)
            std::cout << "  PCAP: " << PcapFilename(prefix, devices.Get(i)) << std::endl;
    }

    // [NEW] NetAnim output
    AnimationInterface anim(animFile);
    SetupNetAnim(anim, nodes,
        {"n0\n10.1.1.1", "n1\n10.1.1.2", "n2\n10.1.1.3", "n3\n10.1.1.4"},
        {{50,130,255},{50,130,255},{50,130,255},{50,130,255}},
        11.0);

    Simulator::Stop(Seconds(10.0));
    Simulator::Run();
    Simulator::Destroy();

    if (g_pcapEnabled) VerifyAnyPcapInDir(outDir);
    std::cout << "  NetAnim: " << animFile << std::endl;
}

// =============================================================================
// =============================================================================
// SCENARIO 2: ARP
// =============================================================================
// =============================================================================
//
// PURPOSE: Observe ARP Request (broadcast) and ARP Reply (unicast) in Wireshark.
// TOPOLOGY: 4 nodes on a single CSMA LAN (10.1.2.0/24).
// TRAFFIC:
//   n0 → n3: UDP Echo triggers ARP for n3's MAC
//   n2 → n1: second flow with separate ARP exchange
//
// GUIDANCE for [C]:
//   ARP triggered automatically by IPv4 stack on cache miss.
//   ArpL3Protocol installed by InternetStackHelper (no manual config needed).
//   ARP Request: EtherType=0x0806, opcode=1, dst=ff:ff:ff:ff:ff:ff (broadcast).
//   ARP Reply:   EtherType=0x0806, opcode=2, dst=<requesting node MAC> (unicast).
//
// GUIDANCE for [W]:
//   Filter "arp"           → all ARP frames
//   Filter "arp.opcode==1" → ARP Requests  (dst=ff:ff:ff:ff:ff:ff)
//   Filter "arp.opcode==2" → ARP Replies   (unicast dst)
//   Fields: arp.src.hw_mac, arp.src.proto_ipv4, arp.dst.hw_mac, arp.dst.proto_ipv4
//   ARP Request MUST precede first UDP/IP data frame.
//
// GUIDANCE for [B+X]:
//   ARP Reply is UNICAST: eth.dst == n0_mac (not broadcast).
//   After ARP completes, subsequent frames go directly to unicast MAC.
//   With different seeds, ARP timing shifts by jitter — compare timestamps.
// =============================================================================
static void
RunArp(const std::string& outDir, const std::string& animFile, double jitter)
{
    std::cout << "\n========================================" << std::endl;
    std::cout << "SCENARIO: arp" << std::endl;
    std::cout << "Seed: " << g_seed << "  (jitter=" << jitter << "s)" << std::endl;
    std::cout << "Output:   " << outDir << std::endl;
    std::cout << "========================================" << std::endl;

    EnsureDirectory(outDir);

    NodeContainer nodes;
    nodes.Create(4);

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", DataRateValue(DataRate("100Mbps")));
    csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));
    NetDeviceContainer devices = csma.Install(nodes);

    // [NEW] Horizontal layout for NetAnim
    SetupMobility(nodes, {{10,50},{30,50},{70,50},{90,50}});

    InternetStackHelper internet;
    internet.SetIpv6StackInstall(false);
    internet.Install(nodes);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer ifaces = ipv4.Assign(devices);

    PrintAddressTable("arp", nodes, devices, ifaces);
    std::cout << "  ARP: n0 (10.1.2.1) ← UDP → n3 (10.1.2.4)" << std::endl;
    std::cout << "  ARP will be triggered on first send (fresh ARP cache)." << std::endl;

    // =========================================================================
    // GUIDANCE for [C]: UdpEchoServer on n3 (port 4000, not 9=DISCARD).
    // UdpEchoClient on n0 → sends 10 packets; first triggers ARP.
    // Second flow n2→n1 shows a separate ARP exchange at a different time.
    // [NEW] jitter shifts start times.
    // =========================================================================
    UdpEchoServerHelper echoServer(DATA_PORT);
    ApplicationContainer serverApp = echoServer.Install(nodes.Get(3));
    serverApp.Start(Seconds(0.5));
    serverApp.Stop(Seconds(9.0));

    ApplicationContainer serverApp2 = echoServer.Install(nodes.Get(1));
    serverApp2.Start(Seconds(0.5));
    serverApp2.Stop(Seconds(9.0));

    UdpEchoClientHelper echoClient(ifaces.GetAddress(3), DATA_PORT);
    echoClient.SetAttribute("MaxPackets", UintegerValue(10));
    echoClient.SetAttribute("Interval", TimeValue(Seconds(0.5)));
    echoClient.SetAttribute("PacketSize", UintegerValue(64));
    ApplicationContainer clientApp = echoClient.Install(nodes.Get(0));
    clientApp.Start(Seconds(1.0 + jitter));
    clientApp.Stop(Seconds(9.0));

    UdpEchoClientHelper echoClient2(ifaces.GetAddress(1), DATA_PORT);
    echoClient2.SetAttribute("MaxPackets", UintegerValue(6));
    echoClient2.SetAttribute("Interval", TimeValue(Seconds(0.8)));
    echoClient2.SetAttribute("PacketSize", UintegerValue(64));
    ApplicationContainer clientApp2 = echoClient2.Install(nodes.Get(2));
    clientApp2.Start(Seconds(2.0 + jitter));
    clientApp2.Stop(Seconds(9.0));

    // =========================================================================
    // GUIDANCE for [W]: Sequence in Wireshark:
    //   t~1s  ARP Request  (n0 → who is 10.1.2.4?)   eth.dst=ff:ff:ff:ff:ff:ff
    //   t~1s  ARP Reply    (n3 → I am at <MAC>)       eth.dst=n0-MAC (unicast)
    //   t~1s  UDP n0→n3 (data), UDP n3→n0 (echo reply)
    //   t~2s  ARP Request  (n2 → who is 10.1.2.2?)
    //   t~2s  ARP Reply    (n1 → unicast to n2)
    // =========================================================================
    if (g_pcapEnabled)
    {
        std::string prefix = outDir + "arp";
        csma.EnablePcap(prefix, devices, true);
        for (uint32_t i = 0; i < devices.GetN(); i++)
            std::cout << "  PCAP: " << PcapFilename(prefix, devices.Get(i)) << std::endl;
    }

    // [NEW] NetAnim output
    AnimationInterface anim(animFile);
    SetupNetAnim(anim, nodes,
        {"n0\n10.1.2.1", "n1\n10.1.2.2", "n2\n10.1.2.3", "n3\n10.1.2.4"},
        {{50,130,255},{50,130,255},{50,130,255},{50,130,255}},
        11.0);

    Simulator::Stop(Seconds(10.0));
    Simulator::Run();
    Simulator::Destroy();

    if (g_pcapEnabled) VerifyAnyPcapInDir(outDir);
    std::cout << "  NetAnim: " << animFile << std::endl;
}

// =============================================================================
// =============================================================================
// SCENARIO 3: SWITCH LEARNING
// =============================================================================
// =============================================================================
//
// PURPOSE: Show MAC learning (flood on unknown → selective unicast after learning).
// TOPOLOGY: 4 terminals on separate CSMA links to a central BridgeNetDevice.
//
// SEQUENCE:
//   1. n0 sends ARP Request (broadcast → bridge FLOODS to all ports)
//      Bridge LEARNS: n0-MAC is on port0
//      n1 and n3 SEE the ARP Request (flooding)
//   2. n2 sends ARP Reply (unicast to n0-MAC)
//      Bridge LEARNS: n2-MAC is on port2
//      Bridge FORWARDS directly to port0 (n0 only)
//      n1 and n3 do NOT see the ARP Reply
//   3. n0 sends ICMP Echo to n2 (unicast, bridge forwards to port2 only)
//      n1 and n3 do NOT see ICMP frames
//
// GUIDANCE for [C]:
//   BridgeHelper::Install(sw, switchDevices) creates a BridgeNetDevice
//   implementing IEEE 802.1D MAC learning. Table is EMPTY initially → flood.
//   No manual forwarding table entries — learning is fully automatic.
//
// GUIDANCE for [W+X]:
//   sw-observer1-*.pcap (n1): ARP broadcast visible; ICMP NOT visible.
//   sw-observer3-*.pcap (n3): same as n1.
//   sw-target-*.pcap (n2):    sees everything (ARP Request, Reply, ICMP).
//   sw-sender-*.pcap (n0):    sees all outgoing + incoming.
//   Filter "eth.dst == ff:ff:ff:ff:ff:ff" → broadcast (flooded frames).
//   Filter "icmp" → should NOT appear in observer PCAP after learning.
//
// GUIDANCE for [B+X]:
//   Run with different seeds: jitter shifts the ARP timing slightly.
//   The key observation (flood→unicast) is independent of seed.
// =============================================================================
static void
RunSwitchLearning(const std::string& outDir, const std::string& animFile, double jitter)
{
    std::cout << "\n========================================" << std::endl;
    std::cout << "SCENARIO: switch-learning" << std::endl;
    std::cout << "Seed: " << g_seed << "  (jitter=" << jitter << "s)" << std::endl;
    std::cout << "Output:   " << outDir << std::endl;
    std::cout << "========================================" << std::endl;

    EnsureDirectory(outDir);

    NodeContainer terminals;
    terminals.Create(4); // n0=sender, n1=observer, n2=target, n3=observer

    NodeContainer switchNode;
    switchNode.Create(1); // bridge, no IP

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", DataRateValue(DataRate("100Mbps")));
    csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));

    NetDeviceContainer terminalDevices;
    NetDeviceContainer switchDevices;

    for (int i = 0; i < 4; i++)
    {
        NetDeviceContainer link = csma.Install(NodeContainer(terminals.Get(i), switchNode.Get(0)));
        terminalDevices.Add(link.Get(0));
        switchDevices.Add(link.Get(1));
    }

    BridgeHelper bridgeHelper;
    bridgeHelper.Install(switchNode.Get(0), switchDevices);

    InternetStackHelper internet;
    internet.SetIpv6StackInstall(false);
    internet.Install(terminals);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer ifaces = ipv4.Assign(terminalDevices);

    PrintAddressTable("switch-learning", terminals, terminalDevices, ifaces);
    std::cout << "  Traffic: n0 (10.1.3.1) pings n2 (10.1.3.3)" << std::endl;
    std::cout << "  Observers: n1, n3 (see ARP flood then silence for unicast)" << std::endl;

    // [NEW] Star layout: switch center, terminals at corners
    // Mobility must cover all 5 nodes (terminals + switch)
    NodeContainer allForMobility(terminals);
    allForMobility.Add(switchNode.Get(0));
    SetupMobility(allForMobility, {{10,80},{10,20},{90,80},{90,20},{50,50}});

    // =========================================================================
    // GUIDANCE for [C]/[B]: n0 pings n2. Generates ARP→ICMP sequence.
    // Count=10 at 0.5s interval ensures MAC learning is visible by packet 3+.
    // [NEW] jitter shifts start; observer PCAP contrast is seed-independent.
    // =========================================================================
    PingHelper ping(ifaces.GetAddress(2));
    ping.SetAttribute("Interval", TimeValue(Seconds(0.5)));
    ping.SetAttribute("Size", UintegerValue(56));
    ping.SetAttribute("Count", UintegerValue(10));
    ApplicationContainer pingApp = ping.Install(terminals.Get(0));
    pingApp.Start(Seconds(1.0 + jitter));
    pingApp.Stop(Seconds(8.0));

    if (g_pcapEnabled)
    {
        std::string prefixSender = outDir + "sw-sender";
        csma.EnablePcap(prefixSender, terminalDevices.Get(0), true);
        std::cout << "  PCAP (n0/sender):   " << PcapFilename(prefixSender, terminalDevices.Get(0)) << std::endl;

        std::string prefixObs1 = outDir + "sw-observer1";
        csma.EnablePcap(prefixObs1, terminalDevices.Get(1), true);
        std::cout << "  PCAP (n1/observer): " << PcapFilename(prefixObs1, terminalDevices.Get(1)) << std::endl;

        std::string prefixTarget = outDir + "sw-target";
        csma.EnablePcap(prefixTarget, terminalDevices.Get(2), true);
        std::cout << "  PCAP (n2/target):   " << PcapFilename(prefixTarget, terminalDevices.Get(2)) << std::endl;

        std::string prefixObs3 = outDir + "sw-observer3";
        csma.EnablePcap(prefixObs3, terminalDevices.Get(3), true);
        std::cout << "  PCAP (n3/observer): " << PcapFilename(prefixObs3, terminalDevices.Get(3)) << std::endl;

        std::string prefixSw = outDir + "sw-port";
        for (uint32_t i = 0; i < switchDevices.GetN(); i++)
            csma.EnablePcap(prefixSw, switchDevices.Get(i), true);
    }

    // [NEW] NetAnim output
    // NOTE: Bridge node has no IP stack, so we do NOT call EnableIpv4L3ProtocolCounters
    // on it. We handle NetAnim setup manually to avoid that call on the bridge.
    AnimationInterface anim(animFile);
    anim.EnablePacketMetadata(true);

    // Labels and colors for terminals
    std::vector<std::string> tLabels = {
        "n0(sender)\n10.1.3.1", "n1(observer)\n10.1.3.2",
        "n2(target)\n10.1.3.3", "n3(observer)\n10.1.3.4"
    };
    std::vector<std::tuple<uint8_t,uint8_t,uint8_t>> tColors = {
        {50,130,255}, {200,200,0}, {0,200,80}, {200,200,0}
    };
    for (uint32_t i = 0; i < terminals.GetN(); ++i)
    {
        anim.UpdateNodeDescription(terminals.Get(i), tLabels[i]);
        auto [r, g, b] = tColors[i];
        anim.UpdateNodeColor(terminals.Get(i), r, g, b);
        anim.UpdateNodeSize(terminals.Get(i)->GetId(), 3.0, 3.0);
    }
    anim.UpdateNodeDescription(switchNode.Get(0), "Switch\n(bridge\nno IP)");
    anim.UpdateNodeColor(switchNode.Get(0), 255, 100, 0);
    anim.UpdateNodeSize(switchNode.Get(0)->GetId(), 4.0, 4.0);

    Simulator::Stop(Seconds(10.0));
    Simulator::Run();
    Simulator::Destroy();

    if (g_pcapEnabled) VerifyAnyPcapInDir(outDir);
    std::cout << "  NetAnim: " << animFile << std::endl;
}

// =============================================================================
// =============================================================================
// SCENARIO 4: CRC (Frame Check Sequence / Error Detection)
// =============================================================================
// =============================================================================
//
// PURPOSE: Demonstrate Ethernet CRC/FCS error detection at the link layer.
// TOPOLOGY: 2 nodes on a shared CSMA LAN, RateErrorModel on n1's receive path.
//
// GUIDANCE for [C]:
//   GlobalValue::Bind("ChecksumEnabled", true) enables CRC-32 FCS computation
//   on every frame (must be set BEFORE node creation).
//   RateErrorModel on n1's CsmaNetDevice::SetReceiveErrorModel() drops
//   g_errorRate fraction of incoming packets, simulating CRC discard.
//   CRC is a LINK LAYER (L2) mechanism; no ICMP or TCP error is generated.
//
// GUIDANCE for [W+X]:
//   Compare frame counts in crc-sender-*.pcap vs crc-receiver-*.pcap.
//   Sender shows all sent frames; receiver shows fewer (missing = CRC discards).
//   In n0's PCAP: "udp.dstport==4000" → sent; "udp.srcport==4000" → echo replies.
//   Missing echo replies = frames dropped by error model.
//   [NEW] Run with different --errorRate values to change drop fraction.
//
// [NEW] --errorRate is configurable (default 0.10 = 10%).
//   If n0 sends 80 UDP packets at rate R, expect n1 to receive ~80*(1-R).
// =============================================================================
static void
RunCrc(const std::string& outDir, const std::string& animFile, double jitter, double errorRate)
{
    std::cout << "\n========================================" << std::endl;
    std::cout << "SCENARIO: crc" << std::endl;
    std::cout << "Seed: " << g_seed << "  (jitter=" << jitter << "s)" << std::endl;
    std::cout << "ErrorRate: " << errorRate << "  (" << (int)(errorRate*100) << "% frame drop)" << std::endl;
    std::cout << "Output:   " << outDir << std::endl;
    std::cout << "========================================" << std::endl;

    EnsureDirectory(outDir);

    // =========================================================================
    // GUIDANCE for [C]: ChecksumEnabled must be set BEFORE nodes are created.
    // =========================================================================
    GlobalValue::Bind("ChecksumEnabled", BooleanValue(true));
    std::cout << "  ChecksumEnabled = true  (Ethernet FCS/CRC-32 active)" << std::endl;

    NodeContainer nodes;
    nodes.Create(2);

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", DataRateValue(DataRate("100Mbps")));
    csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));
    NetDeviceContainer devices = csma.Install(nodes);

    // [NEW] Horizontal layout
    SetupMobility(nodes, {{10,50},{90,50}});

    InternetStackHelper internet;
    internet.SetIpv6StackInstall(false);
    internet.Install(nodes);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.4.0", "255.255.255.0");
    Ipv4InterfaceContainer ifaces = ipv4.Assign(devices);

    PrintAddressTable("crc", nodes, devices, ifaces);

    // =========================================================================
    // GUIDANCE for [C]/[B]: RateErrorModel on n1's receive path.
    // [NEW] errorRate is now configurable via --errorRate (was hardcoded 0.10).
    // =========================================================================
    Ptr<RateErrorModel> errorModel = CreateObject<RateErrorModel>();
    errorModel->SetAttribute("ErrorRate", DoubleValue(errorRate));
    errorModel->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));

    Ptr<CsmaNetDevice> n1Dev = DynamicCast<CsmaNetDevice>(devices.Get(1));
    n1Dev->SetReceiveErrorModel(errorModel);
    std::cout << "  RateErrorModel on n1 receive: ErrorRate="
              << errorRate << " (simulates CRC discard)" << std::endl;

    // =========================================================================
    // GUIDANCE for [C]: n0 sends 80 UDP packets to n1 at 100ms intervals.
    // Expected delivery: ~80*(1-errorRate) packets.
    // [NEW] jitter shifts start time.
    // =========================================================================
    UdpEchoServerHelper server(DATA_PORT);
    ApplicationContainer serverApp = server.Install(nodes.Get(1));
    serverApp.Start(Seconds(0.5));
    serverApp.Stop(Seconds(9.0));

    UdpEchoClientHelper client(ifaces.GetAddress(1), DATA_PORT);
    client.SetAttribute("MaxPackets", UintegerValue(80));
    client.SetAttribute("Interval", TimeValue(MilliSeconds(100)));
    client.SetAttribute("PacketSize", UintegerValue(128));
    ApplicationContainer clientApp = client.Install(nodes.Get(0));
    clientApp.Start(Seconds(1.0 + jitter));
    clientApp.Stop(Seconds(9.0));

    std::cout << "  n0 sends 80 UDP packets to n1 @ 100ms intervals" << std::endl;
    std::cout << "  Expected delivery to n1: ~" << (int)(80*(1.0-errorRate))
              << " packets (" << (int)(errorRate*100) << "% dropped)" << std::endl;

    if (g_pcapEnabled)
    {
        std::string prefixSender   = outDir + "crc-sender";
        std::string prefixReceiver = outDir + "crc-receiver";
        csma.EnablePcap(prefixSender,   devices.Get(0), true);
        csma.EnablePcap(prefixReceiver, devices.Get(1), true);
        std::cout << "  PCAP (n0/sender):   " << PcapFilename(prefixSender,   devices.Get(0)) << std::endl;
        std::cout << "  PCAP (n1/receiver): " << PcapFilename(prefixReceiver, devices.Get(1)) << std::endl;
    }

    // [NEW] NetAnim output
    AnimationInterface anim(animFile);
    SetupNetAnim(anim, nodes,
        {"n0\n10.1.4.1\n(sender)",
         "n1\n10.1.4.2\n(receiver)\nerrorRate=" + std::to_string((int)(errorRate*100)) + "%"},
        {{50,130,255},{255,80,80}},
        11.0);

    Simulator::Stop(Seconds(10.0));
    Simulator::Run();
    Simulator::Destroy();

    // Restore default so subsequent scenarios are unaffected
    GlobalValue::Bind("ChecksumEnabled", BooleanValue(false));

    if (g_pcapEnabled) VerifyAnyPcapInDir(outDir);
    std::cout << "  NetAnim: " << animFile << std::endl;
}

// =============================================================================
// =============================================================================
// SCENARIO 5: VLAN (802.1Q Virtual LAN)
// =============================================================================
// =============================================================================
//
// PURPOSE: Show 802.1Q VLAN-tagged Ethernet frames in Wireshark.
// TOPOLOGY: 4 nodes on a single shared CSMA LAN (raw layer-2, no IP routing).
//
// IMPLEMENTATION: PacketSocket with protocol=0x8100 + VlanTag header prepended.
// Wireshark decodes as proper 802.1Q VLAN frames.
//
// GUIDANCE for [C]:
//   sockAddr.SetProtocol(0x8100) → EtherType in Ethernet frame.
//   pkt->AddHeader(vTag) → TCI + InnerType as first payload bytes.
//   See VlanSenderApp::SendVlanFrame() above.
//   VID=10 and VID=20 are two logical networks sharing one physical medium.
//
// GUIDANCE for [W]:
//   Filter "vlan"         → all 802.1Q frames
//   Filter "vlan.id==10"  → VLAN 10 (n0, n1 senders)
//   Filter "vlan.id==20"  → VLAN 20 (n2, n3 senders)
//   Field: eth.type → must be 0x8100 (TPID)
//   Expand "802.1Q Virtual LAN": Priority (PCP), DEI bit, ID (VID), Type (inner).
//
// GUIDANCE for [V]:
//   VLANs allow a single physical switch to carry traffic for multiple
//   logical networks, providing isolation, security, and reduced broadcast domains.
// =============================================================================
static void
RunVlan(const std::string& outDir, const std::string& animFile, double jitter)
{
    std::cout << "\n========================================" << std::endl;
    std::cout << "SCENARIO: vlan" << std::endl;
    std::cout << "Seed: " << g_seed << "  (jitter=" << jitter << "s)" << std::endl;
    std::cout << "Output:   " << outDir << std::endl;
    std::cout << "  PacketSocket + VlanTag (EtherType=0x8100)" << std::endl;
    std::cout << "========================================" << std::endl;

    EnsureDirectory(outDir);

    NodeContainer nodes;
    nodes.Create(4); // n0,n1 = VLAN 10;  n2,n3 = VLAN 20

    PacketSocketHelper packetSocket;
    packetSocket.Install(nodes);

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", DataRateValue(DataRate("100Mbps")));
    csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));
    NetDeviceContainer devices = csma.Install(nodes);

    // [NEW] Horizontal layout for NetAnim
    SetupMobility(nodes, {{10,50},{30,50},{70,50},{90,50}});

    std::cout << "\n  Node | VLAN | MAC Address         | DevIfIndex" << std::endl;
    std::cout << "  -----|------|---------------------|----------" << std::endl;
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        Ptr<NetDevice> dev = devices.Get(i);
        Mac48Address mac   = Mac48Address::ConvertFrom(dev->GetAddress());
        uint16_t vlanId    = (i < 2) ? 10 : 20;
        std::cout << "  n" << nodes.Get(i)->GetId()
                  << "   | " << vlanId
                  << "  | " << mac
                  << "  | " << dev->GetIfIndex() << std::endl;
    }
    std::cout << std::endl;

    Mac48Address bcastMac("ff:ff:ff:ff:ff:ff");

    // [NEW] jitter shifts start times
    Ptr<VlanSenderApp> vlanApp0 = CreateObject<VlanSenderApp>();
    vlanApp0->Setup(devices.Get(0)->GetIfIndex(), bcastMac, 10, 48);
    nodes.Get(0)->AddApplication(vlanApp0);
    vlanApp0->SetStartTime(Seconds(1.0 + jitter));
    vlanApp0->SetStopTime(Seconds(8.0));

    Ptr<VlanSenderApp> vlanApp1 = CreateObject<VlanSenderApp>();
    vlanApp1->Setup(devices.Get(1)->GetIfIndex(), bcastMac, 10, 48);
    nodes.Get(1)->AddApplication(vlanApp1);
    vlanApp1->SetStartTime(Seconds(1.5 + jitter));
    vlanApp1->SetStopTime(Seconds(8.0));

    Ptr<VlanSenderApp> vlanApp2 = CreateObject<VlanSenderApp>();
    vlanApp2->Setup(devices.Get(2)->GetIfIndex(), bcastMac, 20, 48);
    nodes.Get(2)->AddApplication(vlanApp2);
    vlanApp2->SetStartTime(Seconds(1.0 + jitter));
    vlanApp2->SetStopTime(Seconds(8.0));

    Ptr<VlanSenderApp> vlanApp3 = CreateObject<VlanSenderApp>();
    vlanApp3->Setup(devices.Get(3)->GetIfIndex(), bcastMac, 20, 48);
    nodes.Get(3)->AddApplication(vlanApp3);
    vlanApp3->SetStartTime(Seconds(2.0 + jitter));
    vlanApp3->SetStopTime(Seconds(8.0));

    if (g_pcapEnabled)
    {
        std::string prefix = outDir + "vlan";
        csma.EnablePcap(prefix, devices, true);
        for (uint32_t i = 0; i < devices.GetN(); i++)
            std::cout << "  PCAP (n" << i << "): " << PcapFilename(prefix, devices.Get(i)) << std::endl;
        std::cout << "\n  Wireshark hints:" << std::endl;
        std::cout << "    Filter: vlan           → all 802.1Q frames" << std::endl;
        std::cout << "    Filter: vlan.id==10    → VLAN 10 only (n0, n1 senders)" << std::endl;
        std::cout << "    Filter: vlan.id==20    → VLAN 20 only (n2, n3 senders)" << std::endl;
        std::cout << "    Field:  eth.type       → must be 0x8100" << std::endl;
    }

    // [NEW] NetAnim output
    // NOTE: VLAN scenario has NO IP stack → do NOT call EnableIpv4L3ProtocolCounters.
    AnimationInterface anim(animFile);
    anim.EnablePacketMetadata(true);
    std::vector<std::string> vLabels = {"n0\nVLAN 10", "n1\nVLAN 10", "n2\nVLAN 20", "n3\nVLAN 20"};
    std::vector<std::tuple<uint8_t,uint8_t,uint8_t>> vColors = {
        {50,130,255},{50,130,255},{0,200,80},{0,200,80}
    };
    for (uint32_t i = 0; i < nodes.GetN(); ++i)
    {
        anim.UpdateNodeDescription(nodes.Get(i), vLabels[i]);
        auto [r, g, b] = vColors[i];
        anim.UpdateNodeColor(nodes.Get(i), r, g, b);
        anim.UpdateNodeSize(nodes.Get(i)->GetId(), 3.0, 3.0);
    }

    Simulator::Stop(Seconds(10.0));
    Simulator::Run();
    Simulator::Destroy();

    if (g_pcapEnabled) VerifyAnyPcapInDir(outDir);
    std::cout << "  NetAnim: " << animFile << std::endl;
}

// =============================================================================
// MAIN
// =============================================================================
int
main(int argc, char* argv[])
{
    std::string scenario = "ethernet-basic";
    int         pcap     = 1;   // [NEW] PCAP ON by default
    int         verbose  = 0;

    CommandLine cmd(__FILE__);
    cmd.AddValue("scenario",   "Scenario: ethernet-basic|arp|switch-learning|crc|vlan|all", scenario);
    cmd.AddValue("pcap",       "Enable PCAP capture (1=on, 0=off)", pcap);
    cmd.AddValue("verbose",    "Enable INFO-level ns-3 logging (0=off, 1=on)", verbose);
    cmd.AddValue("seed",       "RNG seed 1-100 (default 100)", g_seed);       // [NEW]
    cmd.AddValue("errorRate",  "Frame error rate 0..1 for crc scenario (default 0.10)", g_errorRate); // [NEW]
    cmd.Parse(argc, argv);

    g_pcapEnabled = (pcap == 1);

    if (verbose == 1)
    {
        LogComponentEnable("LinkLayerLab",    LOG_LEVEL_INFO);
        LogComponentEnable("CsmaNetDevice",   LOG_LEVEL_INFO);
        LogComponentEnable("BridgeNetDevice", LOG_LEVEL_INFO);
    }

    // Validate
    static const std::vector<std::string> validScenarios = {
        "ethernet-basic", "arp", "switch-learning", "crc", "vlan", "all"
    };
    bool valid = false;
    for (const auto& s : validScenarios)
        if (scenario == s) { valid = true; break; }
    if (!valid)
    {
        std::cerr << "ERROR: Unknown scenario '" << scenario << "'" << std::endl;
        std::cerr << "Valid: ethernet-basic | arp | switch-learning | crc | vlan | all" << std::endl;
        return 1;
    }
    if (g_seed < 1 || g_seed > 100)
    {
        std::cerr << "Seed must be 1-100." << std::endl;
        return 1;
    }

    // =========================================================================
    // [NEW] Seed-based randomization.
    // PacketMetadata::Enable() must be called before ANY packet or topology
    // creation — enables full header recording on every packet for NetAnim.
    // =========================================================================
    PacketMetadata::Enable();
    RngSeedManager::SetSeed(g_seed);
    RngSeedManager::SetRun(g_seed);

    // [NEW] Jitter: 0..0.095 s offset on all send times (seed-derived)
    double jitter = (g_seed % 20) * 0.005;

    // [NEW] Output root for this seed
    EnsureDirectory(g_baseDir);
    std::string seedDir = g_baseDir + "seed" + std::to_string(g_seed) + "/";
    EnsureDirectory(seedDir);

    auto makeOutDir  = [&](const std::string& sub) -> std::string {
        std::string p = seedDir + sub + "/";
        EnsureDirectory(p);
        return p;
    };
    auto makeAnim = [&](const std::string& sub) -> std::string {
        return makeOutDir(sub) + "netanim.xml";
    };

    std::cout << "==========================================" << std::endl;
    std::cout << " ns-3 Lab 5: Link Layer and LANs"          << std::endl;
    std::cout << "==========================================" << std::endl;
    std::cout << " Scenario  : " << scenario << std::endl;
    std::cout << " Seed      : " << g_seed << "  (jitter=" << jitter << "s)" << std::endl;
    std::cout << " PCAP      : " << (g_pcapEnabled ? "enabled" : "disabled (pass --pcap=1)") << std::endl;
    std::cout << " ErrorRate : " << g_errorRate << " (crc scenario only)" << std::endl;
    std::cout << " Output    : " << seedDir << std::endl;
    std::cout << "==========================================" << std::endl;

    bool runAll = (scenario == "all");
    bool runEth = runAll || (scenario == "ethernet-basic");
    bool runArp = runAll || (scenario == "arp");
    bool runSw  = runAll || (scenario == "switch-learning");
    bool runCrc = runAll || (scenario == "crc");
    bool runVlan= runAll || (scenario == "vlan");

    if (runEth)  RunEthernetBasic(makeOutDir("ethernet-basic"), makeAnim("ethernet-basic"), jitter);
    if (runArp)  RunArp(makeOutDir("arp"),                      makeAnim("arp"),             jitter);
    if (runSw)   RunSwitchLearning(makeOutDir("switch-learning"),makeAnim("switch-learning"), jitter);
    if (runCrc)  RunCrc(makeOutDir("crc"),                      makeAnim("crc"),             jitter, g_errorRate);
    if (runVlan) RunVlan(makeOutDir("vlan"),                    makeAnim("vlan"),             jitter);

    std::cout << "\n==========================================" << std::endl;
    std::cout << " Simulation complete." << std::endl;
    std::cout << " Output: " << seedDir << std::endl;
    std::cout << "==========================================" << std::endl;

    std::cout << "\nKey Wireshark filters:" << std::endl;
    std::cout << "  eth.type == 0x0800              IPv4 frames" << std::endl;
    std::cout << "  eth.type == 0x0806              ARP frames" << std::endl;
    std::cout << "  eth.type == 0x8100              802.1Q VLAN frames" << std::endl;
    std::cout << "  arp.opcode == 1                 ARP Request (broadcast)" << std::endl;
    std::cout << "  arp.opcode == 2                 ARP Reply (unicast)" << std::endl;
    std::cout << "  eth.dst == ff:ff:ff:ff:ff:ff    Broadcast frames" << std::endl;
    std::cout << "  icmp                            ICMP (ping)" << std::endl;
    std::cout << "  udp.port == 4000                UDP echo (not DISCARD)" << std::endl;
    std::cout << "  vlan.id == 10                   VLAN 10 frames" << std::endl;
    std::cout << "  vlan.id == 20                   VLAN 20 frames" << std::endl;
    std::cout << "  NetAnim: open netanim.xml in each subfolder" << std::endl;

    return 0;
}
