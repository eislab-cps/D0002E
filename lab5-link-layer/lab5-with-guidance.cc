/*
 * =============================================================================
 * ns-3 Wireshark Lab Simulation - Link Layer and LANs
 * =============================================================================
 *
 * Lab 5: Link Layer and LANs (Chapter 6)
 * Course: D0002E — Computer Networking (Kurose & Ross, Top-Down Approach)
 * ns-3 version: 3.46.1
 *
 * =============================================================================
 * EXAMPLE SCRIPTS USED AS BASIS
 * =============================================================================
 *
 * 1. src/csma/examples/csma-one-subnet.cc
 *    - Reused: CsmaHelper setup, InternetStackHelper, Ipv4AddressHelper,
 *      EnablePcapAll pattern for a single shared CSMA LAN.
 *
 * 2. src/bridge/examples/csma-bridge.cc
 *    - Reused: BridgeHelper.Install(switchNode, switchDevices) pattern,
 *      per-terminal CSMA link creation loop, NetDeviceContainer split into
 *      terminalDevices / switchDevices.
 *
 * 3. src/bridge/examples/csma-bridge-one-hop.cc
 *    - Reused: Bridge with multiple separate CSMA segments and routing across
 *      a layer-2 bridge; NodeContainer grouping pattern.
 *
 * 4. src/csma/examples/csma-ping.cc
 *    - Reused: PingHelper on CSMA networks, promiscuous PCAP capture,
 *      pattern for triggering ARP via ICMP.
 *
 * 5. src/csma/examples/csma-packet-socket.cc
 *    - Reused: PacketSocketAddress.SetProtocol(), PacketSocketHelper.Install()
 *      to send raw Layer-2 frames with a custom EtherType (used for VLAN).
 *
 * 6. scratch/d0002e/lab4-with-guidance.cc
 *    - Reused: EnsureDirectory / VerifyPcapFile helpers, overall guidance
 *      comment style, output-directory pattern, port-warning block.
 *
 * =============================================================================
 * HOW TO RUN EACH SCENARIO
 * =============================================================================
 *
 * Build first (from ns-3.46.1 root):
 *   ./ns3 build
 *
 * 1) ETHERNET BASIC (Ethernet frame structure, MAC addresses, EtherType):
 *    ./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=ethernet-basic --pcap=1"
 *    Output: scratch/d0002e/lab 5 output/lab5/ethernet-basic/
 *    Shows:  Ethernet II with src/dst MAC, EtherType=0x0800 (IPv4), ICMP
 *    Wireshark: filter "eth"  → see Ethernet headers
 *               filter "icmp" → see ICMP Echo Request/Reply
 *               filter "arp"  → see ARP Resolution
 *
 * 2) ARP (Address Resolution Protocol – request/reply):
 *    ./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=arp --pcap=1"
 *    Output: scratch/d0002e/lab 5 output/lab5/arp/
 *    Shows:  ARP Request (broadcast), ARP Reply (unicast), then IP traffic
 *    Wireshark: filter "arp"           → all ARP
 *               filter "arp.opcode==1" → ARP Request
 *               filter "arp.opcode==2" → ARP Reply
 *               filter "eth.dst == ff:ff:ff:ff:ff:ff" → broadcast frames
 *
 * 3) SWITCH LEARNING (MAC-learning bridge, flood → selective forward):
 *    ./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=switch-learning --pcap=1"
 *    Output: scratch/d0002e/lab 5 output/lab5/switch-learning/
 *    Shows:  First frames flooded to all ports; later frames forwarded only
 *            to the destination port (observer port goes silent for unicast)
 *    Wireshark: Open sw-observer*.pcap – see ARP flood, then silence for
 *               unicast data; open sw-target*.pcap – see all data traffic
 *
 * 4) CRC (Cyclic Redundancy Check / Frame Check Sequence):
 *    ./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=crc --pcap=1"
 *    Output: scratch/d0002e/lab 5 output/lab5/crc/
 *    Shows:  Normal traffic with FCS enabled; RateErrorModel simulates
 *            CRC-corrupted frames being discarded at the receiver
 *    Wireshark: Compare crc-sender*.pcap vs crc-receiver*.pcap; sender
 *               shows more packets than receiver (dropped by error model)
 *
 * 5) VLAN (802.1Q Virtual LAN tagging):
 *    ./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=vlan --pcap=1"
 *    Output: scratch/d0002e/lab 5 output/lab5/vlan/
 *    Shows:  Ethernet frames with EtherType=0x8100 (802.1Q) containing
 *            VLAN ID 10 and VLAN ID 20 in the Tag Control Information field
 *    Wireshark: filter "vlan"        → all 802.1Q frames
 *               filter "vlan.id==10" → VLAN 10 traffic only
 *               filter "vlan.id==20" → VLAN 20 traffic only
 *               field  eth.type == 0x8100 in Ethernet header
 *
 * 6) ALL SCENARIOS (run all five sequentially):
 *    ./ns3 run "scratch/d0002e/lab5-with-guidance --scenario=all --pcap=1"
 *    Runs each scenario in turn; separate subdirectory per scenario.
 *
 * Additional flags:
 *   --pcap=1      Enable PCAP capture (required for Wireshark analysis)
 *   --verbose=1   Enable ns-3 INFO-level logging
 *
 * =============================================================================
 * NETWORK TOPOLOGY OVERVIEW
 * =============================================================================
 *
 * ETHERNET-BASIC and ARP:
 *
 *   n0 (10.1.1.1) -----+
 *   n1 (10.1.1.2) -----+--- Shared CSMA LAN (100 Mbps, 2 ms delay)
 *   n2 (10.1.1.3) -----+
 *   n3 (10.1.1.4) -----+
 *
 *   Traffic: n0 pings n3 (ICMP Echo → triggers ARP, then data)
 *
 * SWITCH-LEARNING:
 *
 *   n0 (10.1.1.1) ---[link0]---[port0]--+
 *   n1 (10.1.1.2) ---[link1]---[port1]--+--- Bridge/Switch node
 *   n2 (10.1.1.3) ---[link2]---[port2]--+   (no IP stack, layer-2 only)
 *   n3 (10.1.1.4) ---[link3]---[port3]--+
 *
 *   Each terminal is on its own 2-node CSMA segment.
 *   Traffic: n0 pings n2. Observer n1 and n3 capture flooding/silence.
 *
 * CRC:
 *
 *   n0 (10.1.1.1) ---- shared CSMA ---- n1 (10.1.1.2)
 *                                           [RateErrorModel on receive]
 *   Traffic: n0 sends UDP to n1; some frames dropped by error model.
 *
 * VLAN:
 *
 *   n0 (VLAN 10) -----+
 *   n1 (VLAN 10) -----+--- Shared CSMA LAN (raw layer-2 frames, no IP routing)
 *   n2 (VLAN 20) -----+
 *   n3 (VLAN 20) -----+
 *
 *   Frames: EtherType=0x8100, VLAN ID in TCI field; broadcast destination.
 *
 * =============================================================================
 * PORT SELECTION WARNING
 * =============================================================================
 *
 * IMPORTANT: Port 9 is the IANA "DISCARD" service (RFC 863).
 * Using port 9 causes Wireshark to show "Protocol=DISCARD / Info=Discard",
 * which is confusing for students.
 *
 * This script uses port 4000 for all UDP traffic (no well-known service on
 * port 4000; Wireshark shows Protocol=UDP and correct port numbers).
 *
 * Verify: Protocol column must NOT show "DISCARD". Check UDP ports in
 * Wireshark: udp.srcport or udp.dstport should equal 4000.
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
// All PCAP and log files are written under this directory tree.
// Subdirectory per scenario is created automatically.
// =============================================================================
static const std::string g_baseDir = "scratch/d0002e/lab 5 output/lab5/";

// =============================================================================
// PORT CONFIGURATION  –  IMPORTANT: avoid port 9 (DISCARD)
// =============================================================================
// GUIDANCE for [C] question: What port does application traffic use?
// Answer: DATA_PORT = 4000.  UDP/TCP port 9 is the DISCARD service (RFC 863);
// Wireshark shows "DISCARD" for port 9, which is confusing.  We use 4000.
// =============================================================================
static const uint16_t DATA_PORT = 4000;

// Global PCAP flag (set from command line --pcap=1)
static bool g_pcapEnabled = false;

// =============================================================================
// HELPER: Create output directory (and parents)
// =============================================================================
static void
EnsureDirectory(const std::string& path)
{
    std::error_code ec;
    std::filesystem::create_directories(path, ec);
    if (ec)
    {
        std::cerr << "WARNING: could not create directory: " << path
                  << "  (" << ec.message() << ")" << std::endl;
    }
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
        {
            return VerifyPcapFile(entry.path().string());
        }
    }
    std::cerr << "  NO PCAP FILES FOUND in " << dirPath << std::endl;
    return false;
}

// =============================================================================
// HELPER: Print IP/MAC address table for a set of nodes
// =============================================================================
// GUIDANCE for [C] question: Where do MAC addresses come from?
// MAC addresses are automatically assigned by the CsmaHelper when it installs
// a CsmaNetDevice on a node (see CsmaHelper::Install()).  ns-3 allocates
// sequential MAC addresses from the 00:00:00:00:00:01 base.
// IP addresses are assigned by Ipv4AddressHelper (see SetBase/Assign).
// =============================================================================
static void
PrintAddressTable(const std::string& scenarioLabel,
                  NodeContainer nodes,
                  NetDeviceContainer devs,
                  Ipv4InterfaceContainer ifaces)
{
    std::cout << "\n  [" << scenarioLabel << "] Node address table:" << std::endl;
    std::cout << "  Node | IP Address      | MAC Address         | DevIfIndex" << std::endl;
    std::cout << "  -----|-----------------|---------------------|----------" << std::endl;
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        Ptr<NetDevice> dev = devs.Get(i);
        Mac48Address mac    = Mac48Address::ConvertFrom(dev->GetAddress());
        Ipv4Address   ip    = ifaces.GetAddress(i);
        std::cout << "  n" << nodes.Get(i)->GetId()
                  << "   | " << ip
                  << "      | " << mac
                  << "  | " << dev->GetIfIndex()
                  << std::endl;
    }
    std::cout << std::endl;
}

// =============================================================================
// HELPER: Print the expected PCAP filename for a given device
// =============================================================================
static std::string
PcapFilename(const std::string& prefix, Ptr<NetDevice> dev)
{
    // ns-3 naming: prefix-<NodeId>-<DevIfIndex>.pcap
    std::ostringstream oss;
    oss << prefix << "-" << dev->GetNode()->GetId()
        << "-" << dev->GetIfIndex() << ".pcap";
    return oss.str();
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
//  Byte 12-13: TPID = 0x8100  ← signals 802.1Q frame (replaces EtherType)
//  Byte 14-15: TCI  = PCP(3b) | DEI(1b) | VID(12b)   ← VlanTag bytes 0-1
//  Byte 16-17: Inner EtherType (e.g. 0x0800 for IPv4)  ← VlanTag bytes 2-3
//  Byte 18+:  Inner payload
//
// In ns-3 CSMA (DIX mode), setting PacketSocketAddress::SetProtocol(0x8100)
// causes CsmaNetDevice to write 0x8100 as the Ethernet LengthType field.
// We then prepend VlanTag as the first bytes of the packet payload.
// Wireshark sees EtherType=0x8100, reads TCI from next 2 bytes, reads inner
// EtherType from next 2 bytes.
//
// Wireshark fields to inspect:
//   eth.type       → should be 0x8100
//   vlan.id        → VLAN ID (10 or 20 in this scenario)
//   vlan.priority  → Priority Code Point (0 here)
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

    VlanTag() : m_tci(0), m_innerType(0x0800)
    {
    }

    void SetVlanId(uint16_t vid)
    {
        m_tci = (m_tci & 0xF000) | (vid & 0x0FFF);
    }

    void SetPcp(uint8_t pcp)
    {
        m_tci = (m_tci & 0x1FFF) | ((uint16_t)(pcp & 0x07) << 13);
    }

    void SetInnerType(uint16_t t)
    {
        m_innerType = t;
    }

    uint16_t GetVlanId() const
    {
        return m_tci & 0x0FFF;
    }

    TypeId GetInstanceTypeId() const override
    {
        return GetTypeId();
    }

    void Print(std::ostream& os) const override
    {
        os << "VlanTag: VID=" << GetVlanId()
           << " InnerType=0x" << std::hex << m_innerType << std::dec;
    }

    uint32_t GetSerializedSize() const override
    {
        return 4;
    }

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
    uint16_t m_tci;       // Tag Control Information (PCP 3b | DEI 1b | VID 12b)
    uint16_t m_innerType; // Inner EtherType placed after the TCI
};

// =============================================================================
// VLAN SENDER APPLICATION
// =============================================================================
// GUIDANCE for [C] question: How does the VLAN scenario produce 802.1Q frames?
//
// VlanSenderApp uses a PacketSocket (layer-2 raw socket) with protocol=0x8100.
// The CsmaNetDevice (DIX mode) places that protocol number directly into the
// Ethernet EtherType field → Wireshark sees EtherType=0x8100.
//
// The packet payload starts with a VlanTag header (4 bytes):
//   bytes 0-1: TCI  (Priority|DEI|VLAN ID)
//   bytes 2-3: Inner EtherType
// followed by a data payload.
//
// PacketSocketHelper must be installed on the node before creating the socket.
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
        : m_socket(nullptr),
          m_vlanId(10),
          m_devIfIndex(0),
          m_payloadSize(48),
          m_running(false),
          m_pktCount(0)
    {
    }

    virtual ~VlanSenderApp()
    {
        m_socket = nullptr;
    }

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

        // Create a PacketSocket (raw layer-2 socket)
        m_socket = Socket::CreateSocket(GetNode(), PacketSocketFactory::GetTypeId());

        // PacketSocketAddress controls which device and what EtherType to use
        PacketSocketAddress sockAddr;
        sockAddr.SetSingleDevice(m_devIfIndex); // which CSMA NIC
        sockAddr.SetPhysicalAddress(m_dest);    // destination MAC
        sockAddr.SetProtocol(0x8100);           // 802.1Q TPID → sets EtherType in frame

        m_socket->Bind();
        m_socket->Connect(sockAddr);
        SendVlanFrame();
    }

    void StopApplication() override
    {
        m_running = false;
        if (m_socket)
        {
            m_socket->Close();
        }
    }

    void SendVlanFrame()
    {
        if (!m_running)
        {
            return;
        }

        // Build payload (arbitrary data, not real IP – for demo purposes)
        Ptr<Packet> pkt = Create<Packet>(m_payloadSize);

        // Prepend the 4-byte 802.1Q VLAN tag (TCI + InnerEtherType)
        // This is what Wireshark reads after the EtherType=0x8100 field
        VlanTag vTag;
        vTag.SetVlanId(m_vlanId);
        vTag.SetInnerType(0x0800); // inner EtherType: IPv4 (for recognisability)
        pkt->AddHeader(vTag);

        m_socket->Send(pkt);
        m_pktCount++;

        std::cout << "    VLAN " << m_vlanId
                  << " frame #" << m_pktCount
                  << " sent from node " << GetNode()->GetId() << std::endl;

        if (m_running)
        {
            Simulator::Schedule(Seconds(1.0), &VlanSenderApp::SendVlanFrame, this);
        }
    }

    Ptr<Socket> m_socket;
    uint16_t    m_vlanId;
    uint32_t    m_devIfIndex;
    Mac48Address m_dest;
    uint32_t    m_payloadSize;
    bool        m_running;
    uint32_t    m_pktCount;
};

// =============================================================================
// =============================================================================
// SCENARIO 1: ETHERNET BASIC
// =============================================================================
// =============================================================================
//
// PURPOSE: Show the structure of an Ethernet II frame in Wireshark.
//
// TOPOLOGY: 4 nodes on a single shared CSMA LAN (10.1.1.0/24).
//
// TRAFFIC: ICMP Echo (Ping) from n0 to n3.
//   - First packet triggers ARP (shows ARP before IP)
//   - Subsequent packets show Ethernet II + IPv4 + ICMP
//
// =============================================================================
// GUIDANCE for [C] questions:
//   Q: Where does the source MAC address in an Ethernet frame come from?
//   A: It comes from the CsmaNetDevice installed on the sender node.
//      CsmaHelper::Install() calls Node::AddDevice() which registers the NIC.
//      ns-3 auto-assigns sequential MAC addresses starting at 00:00:00:00:00:01.
//      Look for "csma.Install(nodes)" in this function.
//
//   Q: Where does the payload in an Ethernet frame come from?
//   A: From higher-layer protocols.  PingHelper creates an ICMP Echo Request
//      packet.  The IP layer (Ipv4L3Protocol) wraps it in an IPv4 header.
//      The CSMA NIC then adds the Ethernet header (src/dst MAC, EtherType=0x0800
//      for IPv4) and transmits the complete frame.
//
//   Q: What is EtherType 0x0800?
//   A: It identifies the payload as an IPv4 datagram (RFC 7042).
//      ARP uses EtherType 0x0806.
//      802.1Q VLAN uses EtherType 0x8100.
//
// GUIDANCE for [W] questions:
//   - Open any PCAP.  Expand "Ethernet II" header tree in Wireshark.
//   - Fields to find: Source, Destination, Type (0x0800).
//   - Wireshark filter: "eth"   → shows all Ethernet frames
//   - Wireshark filter: "icmp"  → shows only ICMP
//   - Frame length is shown as "Length" in the packet list.
//
// GUIDANCE for [B] questions:
//   - The source MAC in the PCAP must match the MAC printed by this script.
//   - The destination MAC before ARP is resolved will be the broadcast
//     ff:ff:ff:ff:ff:ff (ARP Request); afterwards it is the unicast MAC.
// =============================================================================
static void
RunEthernetBasic(const std::string& outDir)
{
    std::cout << "\n========================================" << std::endl;
    std::cout << "SCENARIO: ethernet-basic" << std::endl;
    std::cout << "Output:   " << outDir << std::endl;
    std::cout << "========================================" << std::endl;

    EnsureDirectory(outDir);

    // =========================================================================
    // GUIDANCE for [C]: Node creation
    // NodeContainer::Create(4) allocates 4 ns-3 Node objects.
    // Each Node gets a unique ID assigned in creation order.
    // =========================================================================
    NodeContainer nodes;
    nodes.Create(4);

    // =========================================================================
    // GUIDANCE for [C]: CSMA channel and device installation
    // CsmaHelper creates a shared CSMA channel (Ethernet bus model).
    // DataRate = link speed; Delay = propagation delay.
    // Install() adds a CsmaNetDevice to EACH node AND connects it to the channel.
    // This is how MAC addresses are created: one per CsmaNetDevice.
    // =========================================================================
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", DataRateValue(DataRate("100Mbps")));
    csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));
    NetDeviceContainer devices = csma.Install(nodes);

    // Install IP stack on all nodes
    InternetStackHelper internet;
    internet.SetIpv6StackInstall(false);
    internet.Install(nodes);

    // =========================================================================
    // GUIDANCE for [C]: IP address assignment
    // Ipv4AddressHelper assigns addresses sequentially from the base.
    //   n0 → 10.1.1.1,  n1 → 10.1.1.2,  n2 → 10.1.1.3,  n3 → 10.1.1.4
    // These appear as the Source/Destination addresses in Wireshark IPv4 header.
    // =========================================================================
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer ifaces = ipv4.Assign(devices);

    PrintAddressTable("ethernet-basic", nodes, devices, ifaces);

    // =========================================================================
    // GUIDANCE for [C]/[B]: Application traffic
    // PingHelper installs an ICMP Echo (Ping) application on node n0.
    // Destination: n3's IP address (10.1.1.4).
    // First ping → ARP Request sent (n0 doesn't know n3's MAC yet).
    // ARP Reply → n3 unicasts its MAC back.
    // Subsequent pings → straight Ethernet + IPv4 + ICMP frames.
    // =========================================================================
    PingHelper ping(ifaces.GetAddress(3)); // n0 pings n3
    ping.SetAttribute("Interval", TimeValue(Seconds(1.0)));
    ping.SetAttribute("Size", UintegerValue(56));
    ApplicationContainer pingApp = ping.Install(nodes.Get(0));
    pingApp.Start(Seconds(1.0));
    pingApp.Stop(Seconds(8.0));

    // =========================================================================
    // GUIDANCE for [W]: PCAP capture points
    // We capture on EVERY node in promiscuous mode so you can see ALL frames
    // on the shared Ethernet bus, including frames not addressed to the
    // capturing node (e.g., ARP broadcasts seen on all nodes).
    //
    // Promiscuous mode (3rd argument = true) ← important for shared LAN.
    //
    // Expected PCAP files (node ID - device interface index):
    //   eth-basic-<nodeId>-<devIfIndex>.pcap  for each node
    //
    // Wireshark key fields:
    //   eth.src            → source MAC
    //   eth.dst            → destination MAC (ff:ff:ff:ff:ff:ff = broadcast)
    //   eth.type           → EtherType (0x0800=IPv4, 0x0806=ARP)
    //   frame.len          → total frame length in bytes
    // =========================================================================
    if (g_pcapEnabled)
    {
        std::string prefix = outDir + "eth-basic";
        csma.EnablePcap(prefix, devices, true); // true = promiscuous
        // Print expected filenames for each device
        for (uint32_t i = 0; i < devices.GetN(); i++)
        {
            std::cout << "  PCAP: " << PcapFilename(prefix, devices.Get(i)) << std::endl;
        }
    }

    Simulator::Stop(Seconds(10.0));
    Simulator::Run();
    Simulator::Destroy();

    if (g_pcapEnabled)
    {
        std::cout << "  Verifying PCAP output..." << std::endl;
        VerifyAnyPcapInDir(outDir);
    }
}

// =============================================================================
// =============================================================================
// SCENARIO 2: ARP
// =============================================================================
// =============================================================================
//
// PURPOSE: Observe ARP Request (broadcast) and ARP Reply (unicast) in Wireshark.
//
// TOPOLOGY: 4 nodes on a single CSMA LAN (10.1.2.0/24).
//
// TRAFFIC:
//   - n0 sends UDP to n3 (unknown at start → triggers ARP)
//   - ARP Request: n0 broadcasts "Who has 10.1.2.4? Tell 10.1.2.1"
//   - ARP Reply:   n3 unicasts "10.1.2.4 is at <n3-MAC>"
//   - UDP data flows after ARP completes
//   - Second exchange: n2 pings n1 (separate ARP for that pair)
//
// =============================================================================
// GUIDANCE for [C] questions:
//   Q: What event triggers ARP?
//   A: ARP is triggered automatically by the IPv4 protocol stack when a node
//      needs to send an IP packet to a destination but does not have a
//      cached MAC address for that IP.  In ns-3, Ipv4L3Protocol calls
//      ArpCache::Lookup(); on a cache miss it queues the IP packet and
//      sends an ARP Request (EtherType=0x0806, opcode=1, dst=broadcast).
//      ARP is handled by ns-3's ArpL3Protocol – you do NOT configure it
//      explicitly; it is installed automatically by InternetStackHelper.
//
//   Q: What is the destination MAC of the ARP Request?
//   A: Always the Ethernet broadcast address: ff:ff:ff:ff:ff:ff.
//      This is how all nodes on the LAN receive the request.
//
//   Q: What is the destination MAC of the ARP Reply?
//   A: The unicast MAC of the requesting node (n0's MAC).
//      Only n0 receives the reply directly.
//
//   Q: What ARP opcodes should I see?
//   A: opcode=1 → ARP Request;   opcode=2 → ARP Reply.
//
// GUIDANCE for [W] questions:
//   - Filter "arp"            → see all ARP frames
//   - Filter "arp.opcode==1"  → ARP Requests only (dst = ff:ff:ff:ff:ff:ff)
//   - Filter "arp.opcode==2"  → ARP Replies only (unicast dst)
//   - Fields in ARP frame:
//       arp.src.hw_mac  → sender's MAC
//       arp.src.proto_ipv4 → sender's IP
//       arp.dst.hw_mac  → target MAC (0s in request, reply MAC in reply)
//       arp.dst.proto_ipv4 → target IP
//   - The ARP Request MUST come before the first UDP/IP data frame.
//
// GUIDANCE for [B] questions:
//   - Match the MAC in arp.src.hw_mac against the address printed by
//     this script for n0 and n3.
//   - Confirm the ARP Reply is unicast (eth.dst == n0_mac, not broadcast).
// =============================================================================
static void
RunArp(const std::string& outDir)
{
    std::cout << "\n========================================" << std::endl;
    std::cout << "SCENARIO: arp" << std::endl;
    std::cout << "Output:   " << outDir << std::endl;
    std::cout << "========================================" << std::endl;

    EnsureDirectory(outDir);

    NodeContainer nodes;
    nodes.Create(4);

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", DataRateValue(DataRate("100Mbps")));
    csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));
    NetDeviceContainer devices = csma.Install(nodes);

    InternetStackHelper internet;
    internet.SetIpv6StackInstall(false);
    internet.Install(nodes);

    // =========================================================================
    // Use 10.1.2.0/24 to distinguish from ethernet-basic subnet
    // =========================================================================
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer ifaces = ipv4.Assign(devices);

    PrintAddressTable("arp", nodes, devices, ifaces);

    std::cout << "  ARP scenario: n0 (10.1.2.1) ← UDP → n3 (10.1.2.4)" << std::endl;
    std::cout << "  ARP will be triggered on first send (fresh ARP cache)." << std::endl;

    // =========================================================================
    // GUIDANCE for [C]: UDP Echo Server on n3
    // UdpEchoServer listens on DATA_PORT (4000).  Port 4000 is safe –
    // Wireshark shows Protocol=UDP, not DISCARD (which happens with port 9).
    // =========================================================================
    UdpEchoServerHelper echoServer(DATA_PORT);
    ApplicationContainer serverApp = echoServer.Install(nodes.Get(3));
    serverApp.Start(Seconds(0.5));
    serverApp.Stop(Seconds(9.0));

    // Also a server on n1 for the second flow (n2→n1)
    ApplicationContainer serverApp2 = echoServer.Install(nodes.Get(1));
    serverApp2.Start(Seconds(0.5));
    serverApp2.Stop(Seconds(9.0));

    // =========================================================================
    // GUIDANCE for [C]: UDP Echo Client on n0 → sends to n3
    // MaxPackets=1: sends one packet at t=1s → triggers ONE ARP cycle.
    // Subsequent packets (MaxPackets=10) continue with the resolved MAC.
    // =========================================================================
    UdpEchoClientHelper echoClient(ifaces.GetAddress(3), DATA_PORT);
    echoClient.SetAttribute("MaxPackets", UintegerValue(10));
    echoClient.SetAttribute("Interval", TimeValue(Seconds(0.5)));
    echoClient.SetAttribute("PacketSize", UintegerValue(64));
    ApplicationContainer clientApp = echoClient.Install(nodes.Get(0));
    clientApp.Start(Seconds(1.0));
    clientApp.Stop(Seconds(9.0));

    // Second flow: n2 → n1 (separate ARP exchange at a slightly different time)
    UdpEchoClientHelper echoClient2(ifaces.GetAddress(1), DATA_PORT);
    echoClient2.SetAttribute("MaxPackets", UintegerValue(6));
    echoClient2.SetAttribute("Interval", TimeValue(Seconds(0.8)));
    echoClient2.SetAttribute("PacketSize", UintegerValue(64));
    ApplicationContainer clientApp2 = echoClient2.Install(nodes.Get(2));
    clientApp2.Start(Seconds(2.0));
    clientApp2.Stop(Seconds(9.0));

    // =========================================================================
    // GUIDANCE for [W]: PCAP capture
    // Capture on ALL nodes in promiscuous mode.
    // In Wireshark, you will see the sequence:
    //   t~1.0s  ARP Request  (n0 asks: who is 10.1.2.4?)   eth.dst=ff:ff:ff:ff:ff:ff
    //   t~1.0s  ARP Reply    (n3 answers: I am at <MAC>)    eth.dst=n0-MAC (unicast)
    //   t~1.0s  UDP (n0→n3)  First data packet (now routed)
    //   t~1.0s  UDP (n3→n0)  Echo reply
    //   ...
    //   t~2.0s  ARP Request  (n2 asks: who is 10.1.2.2?)
    //   t~2.0s  ARP Reply    (n1 answers)
    //   ...
    // =========================================================================
    if (g_pcapEnabled)
    {
        std::string prefix = outDir + "arp";
        csma.EnablePcap(prefix, devices, true);
        for (uint32_t i = 0; i < devices.GetN(); i++)
        {
            std::cout << "  PCAP: " << PcapFilename(prefix, devices.Get(i)) << std::endl;
        }
    }

    Simulator::Stop(Seconds(10.0));
    Simulator::Run();
    Simulator::Destroy();

    if (g_pcapEnabled)
    {
        std::cout << "  Verifying PCAP output..." << std::endl;
        VerifyAnyPcapInDir(outDir);
    }
}

// =============================================================================
// =============================================================================
// SCENARIO 3: SWITCH LEARNING
// =============================================================================
// =============================================================================
//
// PURPOSE: Show MAC learning (flooding on unknown destination, unicast
//          forwarding after learning) in a layer-2 switch/bridge.
//
// TOPOLOGY: 4 terminals each on a separate 2-node CSMA segment,
//           all connected to a central bridge (switch) node.
//
//   n0 (10.1.3.1) ---[csma-link0]---[swport0]--+
//   n1 (10.1.3.2) ---[csma-link1]---[swport1]--+--- Bridge (sw, no IP)
//   n2 (10.1.3.3) ---[csma-link2]---[swport2]--+
//   n3 (10.1.3.4) ---[csma-link3]---[swport3]--+
//
// TRAFFIC: n0 pings n2 (ICMP).
//   - Observers: n1 and n3 capture on their link to see flooding vs silence.
//
// SEQUENCE:
//   1. n0 sends ARP Request (broadcast, dst=ff:ff:ff:ff:ff:ff)
//      → Bridge receives on swport0, FLOODS to swport1, swport2, swport3
//      → Bridge LEARNS: n0-MAC is on swport0
//      → n1 and n3 see the ARP Request on their links (flooding in action)
//   2. n2 sends ARP Reply (unicast to n0-MAC)
//      → Bridge receives on swport2, LEARNS: n2-MAC is on swport2
//      → Bridge already knows n0 is on swport0 → DIRECT FORWARD to swport0
//      → n1 and n3 do NOT see the ARP Reply (selective forwarding)
//   3. n0 sends ICMP Echo to n2
//      → Bridge knows n2 is on swport2 → DIRECT FORWARD to swport2
//      → n1 and n3 do NOT see this frame (selective forwarding)
//   4. n2 sends ICMP Reply to n0
//      → Bridge knows n0 is on swport0 → DIRECT FORWARD to swport0
//      → n1 and n3 do NOT see this frame
//
// OBSERVATION: n1's observer PCAP shows ONLY the ARP broadcast (step 1).
//              Everything else is silenced after MAC learning.
//
// =============================================================================
// GUIDANCE for [C] questions:
//   Q: How is the switch (bridge) created?
//   A: A dedicated Node (sw) is created.  For each terminal n_i, a 2-node
//      CSMA link is installed between n_i and sw.  The sw-side device is
//      added to switchDevices.  BridgeHelper::Install(sw, switchDevices)
//      creates a BridgeNetDevice that aggregates all switch-side devices.
//      The BridgeNetDevice implements IEEE 802.1D MAC learning: when a frame
//      arrives on a port, the source MAC is stored with that port number.
//
//   Q: Is the forwarding table manually configured?
//   A: NO.  The BridgeNetDevice builds its forwarding table (MAC table)
//      dynamically by observing source MACs of incoming frames.
//      Initially the table is EMPTY → every unknown-destination frame is
//      FLOODED to all ports except the one it arrived on.
//
//   Q: What is "flooding" in a switch context?
//   A: When the switch receives a frame with a destination MAC not in its
//      table, it sends the frame out ALL other ports.  This guarantees
//      delivery but wastes bandwidth.  After learning, it uses unicast.
//
// GUIDANCE for [W] questions:
//   Open sw-observer1-*.pcap (n1's link) in Wireshark.
//   You should see:
//     - ARP Request from n0 (broadcast, flooded) → visible on n1's link
//     - NO ARP Reply from n2 (unicast direct to n0, bypasses n1)
//     - NO ICMP frames (unicast direct, n1 not in path)
//   Open sw-target-*.pcap (n2's link) in Wireshark.
//   You should see everything: ARP Request (flooded), ARP Reply, all ICMP.
//   Open sw-sender-*.pcap (n0's link) to see all outgoing and incoming.
//
//   Wireshark filter "eth.dst == ff:ff:ff:ff:ff:ff" shows broadcast (flood).
//   Wireshark filter "icmp" shows ping traffic (should NOT appear in observer).
// =============================================================================
static void
RunSwitchLearning(const std::string& outDir)
{
    std::cout << "\n========================================" << std::endl;
    std::cout << "SCENARIO: switch-learning" << std::endl;
    std::cout << "Output:   " << outDir << std::endl;
    std::cout << "========================================" << std::endl;

    EnsureDirectory(outDir);

    // =========================================================================
    // GUIDANCE for [C]: Separate terminal nodes and bridge/switch node
    // The bridge (sw) has NO Internet stack and NO IP address.
    // It is purely a layer-2 device.
    // =========================================================================
    NodeContainer terminals;
    terminals.Create(4); // n0, n1, n2, n3

    NodeContainer switchNode;
    switchNode.Create(1); // sw (bridge, no IP)

    // Nodes: n0=terminal 0, n1=terminal 1, n2=terminal 2, n3=terminal 3

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", DataRateValue(DataRate("100Mbps")));
    csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));

    // =========================================================================
    // GUIDANCE for [C]: Per-terminal CSMA link installation
    // Each terminal gets its own 2-node CSMA segment to the switch.
    // This means: n0 and sw share csma-link0; n1 and sw share csma-link1; etc.
    // The sw-side device of each link is collected in switchDevices.
    // The terminal-side devices are collected in terminalDevices.
    // =========================================================================
    NetDeviceContainer terminalDevices; // terminal-side devices (n0,n1,n2,n3)
    NetDeviceContainer switchDevices;   // switch-side devices (ports)

    for (int i = 0; i < 4; i++)
    {
        NetDeviceContainer link = csma.Install(NodeContainer(terminals.Get(i), switchNode.Get(0)));
        terminalDevices.Add(link.Get(0)); // terminal device
        switchDevices.Add(link.Get(1));   // switch port device
    }

    // =========================================================================
    // GUIDANCE for [C]: BridgeHelper creates the learning bridge
    // BridgeHelper::Install(sw, switchDevices) aggregates all switch-side
    // devices under a single BridgeNetDevice.  The BridgeNetDevice implements
    // IEEE 802.1D spanning-tree-free MAC learning.
    // NO manual forwarding table entries are added – learning is automatic.
    // =========================================================================
    BridgeHelper bridgeHelper;
    bridgeHelper.Install(switchNode.Get(0), switchDevices);

    // Install IP stack ONLY on terminals (not on bridge)
    InternetStackHelper internet;
    internet.SetIpv6StackInstall(false);
    internet.Install(terminals);

    // Assign IP addresses to terminal devices
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer ifaces = ipv4.Assign(terminalDevices);

    PrintAddressTable("switch-learning", terminals, terminalDevices, ifaces);

    std::cout << "  Traffic: n0 (10.1.3.1) pings n2 (10.1.3.3)" << std::endl;
    std::cout << "  Observers: n1 port (sees ARP flood, then silence)" << std::endl;
    std::cout << "             n3 port (sees ARP flood, then silence)" << std::endl;

    // =========================================================================
    // GUIDANCE for [C]/[B]: Ping application
    // n0 pings n2.  This generates:
    //   ARP Request (broadcast → flooded by bridge to ALL ports including n1,n3)
    //   ARP Reply   (unicast → bridge forwards ONLY to n0's port)
    //   ICMP Echo   (unicast → bridge forwards ONLY to n2's port)
    //   ICMP Reply  (unicast → bridge forwards ONLY to n0's port)
    // =========================================================================
    PingHelper ping(ifaces.GetAddress(2)); // n0 pings n2
    ping.SetAttribute("Interval", TimeValue(Seconds(0.5)));
    ping.SetAttribute("Size", UintegerValue(56));
    ping.SetAttribute("Count", UintegerValue(10));
    ApplicationContainer pingApp = ping.Install(terminals.Get(0));
    pingApp.Start(Seconds(1.0));
    pingApp.Stop(Seconds(8.0));

    // =========================================================================
    // GUIDANCE for [W]: PCAP capture on each terminal link
    // Promiscuous mode (true) is used so we capture all frames on each link.
    //
    // KEY OBSERVATION in Wireshark:
    //   sw-observer1-*.pcap → n1's link:
    //     SHOULD contain: ARP Request from n0 (broadcast, flooded)
    //     SHOULD NOT contain: ARP Reply, ICMP (unicast, not flooded to n1)
    //
    //   sw-observer3-*.pcap → n3's link:
    //     Same as n1: sees ARP broadcast, does NOT see unicast traffic
    //
    //   sw-target-*.pcap → n2's link:
    //     Sees: ARP Request (flooded), ARP Reply (from n2 itself), ICMP
    //
    //   sw-sender-*.pcap → n0's link:
    //     Sees: everything (outgoing ARP request, incoming ARP reply, ICMP)
    // =========================================================================
    if (g_pcapEnabled)
    {
        // n0 = sender
        std::string prefixSender = outDir + "sw-sender";
        csma.EnablePcap(prefixSender, terminalDevices.Get(0), true);
        std::cout << "  PCAP (n0/sender):   " << PcapFilename(prefixSender, terminalDevices.Get(0)) << std::endl;

        // n1 = observer (should see flood, then silence)
        std::string prefixObs1 = outDir + "sw-observer1";
        csma.EnablePcap(prefixObs1, terminalDevices.Get(1), true);
        std::cout << "  PCAP (n1/observer): " << PcapFilename(prefixObs1, terminalDevices.Get(1)) << std::endl;

        // n2 = target (should see everything)
        std::string prefixTarget = outDir + "sw-target";
        csma.EnablePcap(prefixTarget, terminalDevices.Get(2), true);
        std::cout << "  PCAP (n2/target):   " << PcapFilename(prefixTarget, terminalDevices.Get(2)) << std::endl;

        // n3 = observer (same as n1)
        std::string prefixObs3 = outDir + "sw-observer3";
        csma.EnablePcap(prefixObs3, terminalDevices.Get(3), true);
        std::cout << "  PCAP (n3/observer): " << PcapFilename(prefixObs3, terminalDevices.Get(3)) << std::endl;

        // Also capture on the bridge switch-side ports for completeness
        std::string prefixSw = outDir + "sw-port";
        for (uint32_t i = 0; i < switchDevices.GetN(); i++)
        {
            csma.EnablePcap(prefixSw, switchDevices.Get(i), true);
        }
    }

    Simulator::Stop(Seconds(10.0));
    Simulator::Run();
    Simulator::Destroy();

    if (g_pcapEnabled)
    {
        std::cout << "  Verifying PCAP output..." << std::endl;
        VerifyAnyPcapInDir(outDir);
    }
}

// =============================================================================
// =============================================================================
// SCENARIO 4: CRC (Frame Check Sequence / Error Detection)
// =============================================================================
// =============================================================================
//
// PURPOSE: Demonstrate Ethernet CRC/FCS error detection at the link layer.
//
// TOPOLOGY: 2 nodes on a single CSMA LAN.
//
//   n0 (10.1.4.1) ---- shared CSMA ---- n1 (10.1.4.2)
//                                           ^ RateErrorModel (10% drop)
//
// TRAFFIC: n0 sends UDP packets to n1 continuously for 8 seconds.
//
// CRC SIMULATION APPROACH:
//   ns-3 supports real Ethernet FCS (CRC-32) computation when
//   GlobalValue "ChecksumEnabled" is set to true.  This makes the
//   CsmaNetDevice compute and verify the FCS on every frame.
//
//   To simulate CRC errors (corrupt frames being discarded), we attach
//   a RateErrorModel to n1's receive path.  The error model randomly
//   marks a fraction of incoming packets as "lost" BEFORE the IP stack
//   processes them, simulating what a real NIC does when it detects a
//   CRC mismatch: silently discard the frame.
//
// OBSERVATION:
//   n0's PCAP shows all sent frames.
//   n1's PCAP (promiscuous) shows frames arriving at the wire level.
//   However, n1's IP/UDP statistics show fewer received datagrams
//   (because the error model drops some before they reach the IP stack).
//   This represents what happens when CRC detects a corrupted frame.
//
// =============================================================================
// GUIDANCE for [C] questions:
//   Q: What is CRC/FCS in Ethernet?
//   A: The Frame Check Sequence (FCS) is a 4-byte CRC-32 checksum appended
//      to every Ethernet frame by the sender.  The receiver recomputes the
//      CRC over the received frame and compares.  A mismatch → frame is
//      silently discarded (no retransmission at layer 2; that is handled
//      by higher-layer protocols like TCP).
//
//   Q: How is CRC enabled in this script?
//   A: GlobalValue::Bind("ChecksumEnabled", BooleanValue(true)) tells ns-3
//      to compute and verify real checksums including Ethernet FCS.
//      Without this, ns-3 uses dummy (all-zero) checksums for performance.
//
//   Q: How are "CRC errors" simulated?
//   A: A RateErrorModel is attached to n1's CsmaNetDevice receive path.
//      SetAttribute("ErrorRate", 0.1) → 10% of received packets are dropped.
//      SetAttribute("ErrorUnit", ERROR_UNIT_PACKET) → whole-packet drops.
//      This mimics NIC behavior: corrupt frame detected by CRC → discard.
//
//   Q: At which layer does CRC operate?
//   A: CRC is a LINK LAYER (Layer 2) mechanism.  It protects the frame
//      in transit on ONE link segment.  It is NOT end-to-end (that is
//      TCP checksum at Layer 4).  If a frame is corrupted in transit,
//      the receiving NIC drops it; no ICMP or TCP error is generated.
//
// GUIDANCE for [W] questions:
//   - Open crc-sender-*.pcap in Wireshark.  Count UDP frames.
//   - Open crc-receiver-*.pcap in Wireshark.  Count UDP frames received.
//   - The receiver PCAP will show fewer frames (missing = "CRC discards").
//   - In real captures with Wireshark + Ethernet adapter: if "FCS validation"
//     is enabled (Edit → Preferences → Protocols → Ethernet → Validate FCS),
//     Wireshark marks corrupt frames in red and shows "Bad FCS" in the tree.
//   - In ns-3 PCAP, corrupted frames are NEVER written to the receiver PCAP
//     because they are dropped by the error model before being forwarded.
//     The "gap" (missing packets between sequence numbers) is the observable.
//   - Use Wireshark "Statistics → Capture File Properties" to compare
//     frame counts between sender and receiver PCAPs.
//
// GUIDANCE for [B] questions:
//   - The error rate is 10% (configured in code below, search "ErrorRate").
//   - If n0 sends 80 UDP packets, expect n1 to receive ~72 (10% dropped).
//   - You can adjust ErrorRate in code and re-run to observe different loss.
// =============================================================================
static void
RunCrc(const std::string& outDir)
{
    std::cout << "\n========================================" << std::endl;
    std::cout << "SCENARIO: crc" << std::endl;
    std::cout << "Output:   " << outDir << std::endl;
    std::cout << "========================================" << std::endl;

    EnsureDirectory(outDir);

    // =========================================================================
    // GUIDANCE for [C]: Enable real Ethernet FCS (CRC-32) computation
    // This global setting must be made BEFORE nodes are created.
    // It applies to all CSMA and other network devices in this simulation.
    // =========================================================================
    GlobalValue::Bind("ChecksumEnabled", BooleanValue(true));
    std::cout << "  ChecksumEnabled = true  (Ethernet FCS/CRC-32 active)" << std::endl;

    NodeContainer nodes;
    nodes.Create(2);

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", DataRateValue(DataRate("100Mbps")));
    csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));
    NetDeviceContainer devices = csma.Install(nodes);

    InternetStackHelper internet;
    internet.SetIpv6StackInstall(false);
    internet.Install(nodes);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.4.0", "255.255.255.0");
    Ipv4InterfaceContainer ifaces = ipv4.Assign(devices);

    PrintAddressTable("crc", nodes, devices, ifaces);

    // =========================================================================
    // GUIDANCE for [C]/[B]: Attach RateErrorModel to n1's receive path
    //
    // RateErrorModel drops packets randomly at the configured rate.
    // ErrorRate = 0.10 → 10% of frames dropped (simulating CRC discard).
    // ERROR_UNIT_PACKET → one entire packet per error event (not bit-level).
    //
    // The model is attached to the CsmaNetDevice on n1 (the receiver).
    // The sender n0 is NOT affected (its transmit path is clean).
    // =========================================================================
    Ptr<RateErrorModel> errorModel = CreateObject<RateErrorModel>();
    errorModel->SetAttribute("ErrorRate", DoubleValue(0.10));   // 10% CRC error rate
    errorModel->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));

    // Attach error model to n1's receive device
    Ptr<CsmaNetDevice> n1Dev = DynamicCast<CsmaNetDevice>(devices.Get(1));
    n1Dev->SetReceiveErrorModel(errorModel);
    std::cout << "  RateErrorModel on n1 receive: ErrorRate=10% (simulates CRC discard)" << std::endl;

    // =========================================================================
    // GUIDANCE for [C]: Application traffic
    // n0 sends UDP to n1 (port 4000, not port 9 which is DISCARD).
    // Sending every 100ms for 8 seconds → ~80 packets expected.
    // ~72 should arrive at n1 (90% success with 10% error rate).
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
    clientApp.Start(Seconds(1.0));
    clientApp.Stop(Seconds(9.0));

    std::cout << "  n0 sends 80 UDP packets to n1 @ 100ms intervals" << std::endl;
    std::cout << "  Expected delivery to n1 IP stack: ~72 packets (10% dropped)" << std::endl;

    // =========================================================================
    // GUIDANCE for [W]: PCAP capture on both nodes
    // crc-sender-*  = n0's perspective (should show all sent frames)
    // crc-receiver-* = n1's perspective (may show fewer if driver-level capture)
    //
    // NOTE on PCAP and error model:
    //   In ns-3, PCAP hooks are called at the CsmaNetDevice::Receive() point
    //   BEFORE the error model runs.  This means n1's PCAP may still show all
    //   frames at the wire level.  The error model discards frames AFTER capture,
    //   so the effect is visible in application-level packet counts, not PCAP.
    //   In real hardware, the NIC discards corrupt frames BEFORE the OS sees them,
    //   so they do not appear in Wireshark captures either.
    //
    //   To observe the "missing" effect: compare the application-level echo
    //   replies (n0 should receive fewer echo replies than it sent requests).
    //   Filter in Wireshark on n0's PCAP:
    //     "udp.dstport==4000" → sent requests
    //     "udp.srcport==4000" → received echo replies
    //   Count the difference = frames dropped by error model.
    // =========================================================================
    if (g_pcapEnabled)
    {
        std::string prefixSender   = outDir + "crc-sender";
        std::string prefixReceiver = outDir + "crc-receiver";
        csma.EnablePcap(prefixSender,   devices.Get(0), true);
        csma.EnablePcap(prefixReceiver, devices.Get(1), true);
        std::cout << "  PCAP (n0/sender):   " << PcapFilename(prefixSender, devices.Get(0)) << std::endl;
        std::cout << "  PCAP (n1/receiver): " << PcapFilename(prefixReceiver, devices.Get(1)) << std::endl;
    }

    Simulator::Stop(Seconds(10.0));
    Simulator::Run();
    Simulator::Destroy();

    // =========================================================================
    // Restore default checksum setting so subsequent scenarios are unaffected
    // =========================================================================
    GlobalValue::Bind("ChecksumEnabled", BooleanValue(false));

    if (g_pcapEnabled)
    {
        std::cout << "  Verifying PCAP output..." << std::endl;
        VerifyAnyPcapInDir(outDir);
    }
}

// =============================================================================
// =============================================================================
// SCENARIO 5: VLAN (802.1Q Virtual LAN)
// =============================================================================
// =============================================================================
//
// PURPOSE: Show 802.1Q VLAN-tagged Ethernet frames in Wireshark.
//
// IMPLEMENTATION NOTES:
//   ns-3 3.46.1 does not provide a built-in VLAN-aware switch or 802.1Q
//   encapsulation helper for CSMA devices.  However, the ns-3 CSMA NIC
//   operates in DIX (Ethernet II) mode by default, which means the
//   "protocol number" passed to the NIC's Send() method is placed verbatim
//   into the Ethernet EtherType field.
//
//   We exploit this to produce genuine 802.1Q frames:
//   1. Install PacketSocketHelper on nodes (enables raw layer-2 sockets).
//   2. Create VlanSenderApp which uses PacketSocket with protocol=0x8100.
//      → CsmaNetDevice writes EtherType=0x8100 in the Ethernet frame.
//   3. VlanSenderApp prepends a 4-byte VlanTag header (TCI + InnerEtherType)
//      as the first bytes of the packet.
//      → Wireshark reads: [EtherType=0x8100][TCI][InnerType][payload]
//      → Wireshark decodes this as a proper 802.1Q VLAN frame.
//
//   This approach produces PCAP files that Wireshark correctly decodes as
//   802.1Q Virtual LAN frames.
//
// TOPOLOGY: 4 nodes on a single shared CSMA LAN (no IP routing needed).
//
//   n0 (VLAN 10) -----+
//   n1 (VLAN 10) -----+--- Shared CSMA LAN (raw layer-2)
//   n2 (VLAN 20) -----+
//   n3 (VLAN 20) -----+
//
// TRAFFIC:
//   n0 sends VLAN 10 broadcast frames every 1s
//   n2 sends VLAN 20 broadcast frames every 1s
//   All 4 nodes capture in promiscuous mode
//
// =============================================================================
// GUIDANCE for [C] questions:
//   Q: How are VLAN-tagged frames produced without a VLAN-aware switch?
//   A: By using a raw PacketSocket with protocol=0x8100.  The key lines are:
//        sockAddr.SetProtocol(0x8100);  // → EtherType in Ethernet frame
//        pkt->AddHeader(vTag);           // → TCI + InnerType as payload start
//      See VlanSenderApp::SendVlanFrame() above.
//
//   Q: What is the purpose of the VLAN ID (VID)?
//   A: VID identifies the virtual LAN.  VID=10 and VID=20 are two separate
//      logical networks sharing the same physical medium.  A VLAN-aware switch
//      would forward VLAN 10 frames only to VLAN 10 ports, isolating traffic.
//      In this scenario (no VLAN switch), all frames are visible on the shared
//      medium, but VLAN separation is enforced by software/protocol.
//
//   Q: What is the TCI field?
//   A: Tag Control Information (2 bytes):
//        bits 15-13: PCP (Priority Code Point)
//        bit  12:    DEI (Drop Eligible Indicator)
//        bits 11-0:  VID (VLAN Identifier, 0-4095)
//
//   Q: What EtherType signals a 802.1Q frame?
//   A: EtherType = 0x8100 (called TPID, Tag Protocol Identifier).
//
// GUIDANCE for [W] questions:
//   - Open vlan-*.pcap in Wireshark.
//   - Filter "vlan"         → all 802.1Q frames
//   - Filter "vlan.id==10"  → VLAN 10 frames only (from n0)
//   - Filter "vlan.id==20"  → VLAN 20 frames only (from n2)
//   - Expand "802.1Q Virtual LAN" header in packet tree:
//       Priority: PCP field (0 = Best Effort)
//       DEI bit
//       ID: VLAN ID (10 or 20)
//       Type: Inner EtherType (0x0800)
//   - "eth.type == 0x8100" in Wireshark filter shows all 802.1Q frames
//
// GUIDANCE for [B] questions:
//   - Verify that eth.type in the PCAP is 0x8100 (not 0x0800 = plain IPv4).
//   - The VLAN ID in the PCAP should match what is coded: 10 and 20.
//   - Compare VlanSenderApp::SendVlanFrame() (code) with Wireshark fields.
// =============================================================================
static void
RunVlan(const std::string& outDir)
{
    std::cout << "\n========================================" << std::endl;
    std::cout << "SCENARIO: vlan" << std::endl;
    std::cout << "Output:   " << outDir << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  Implementation: PacketSocket + VlanTag header (EtherType=0x8100)" << std::endl;
    std::cout << "  Wireshark will decode frames as proper 802.1Q VLAN." << std::endl;

    EnsureDirectory(outDir);

    NodeContainer nodes;
    nodes.Create(4); // n0, n1 = VLAN 10;  n2, n3 = VLAN 20

    // =========================================================================
    // GUIDANCE for [C]: PacketSocketHelper must be installed before
    // VlanSenderApp creates sockets.  PacketSocket is a raw layer-2 socket
    // that bypasses the IP stack entirely, sending directly from layer 2.
    // =========================================================================
    PacketSocketHelper packetSocket;
    packetSocket.Install(nodes);

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", DataRateValue(DataRate("100Mbps")));
    csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));
    // DIX mode (default) is required: protocol number → EtherType directly
    NetDeviceContainer devices = csma.Install(nodes);

    std::cout << "\n  Node | VLAN | MAC Address         | DevIfIndex" << std::endl;
    std::cout << "  -----|------|---------------------|----------" << std::endl;
    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        Ptr<NetDevice> dev = devices.Get(i);
        Mac48Address mac    = Mac48Address::ConvertFrom(dev->GetAddress());
        uint16_t vlanId    = (i < 2) ? 10 : 20;
        std::cout << "  n" << nodes.Get(i)->GetId()
                  << "   | " << vlanId
                  << "  | " << mac
                  << "  | " << dev->GetIfIndex()
                  << std::endl;
    }
    std::cout << std::endl;

    // =========================================================================
    // GUIDANCE for [C]: VLAN sender applications
    // n0 → VLAN 10 broadcast frames (dst = ff:ff:ff:ff:ff:ff)
    // n2 → VLAN 20 broadcast frames
    // Broadcast destination ensures all nodes on the shared LAN receive them
    // so promiscuous PCAP on any node shows both VLAN 10 and VLAN 20 frames.
    // =========================================================================
    Mac48Address bcastMac("ff:ff:ff:ff:ff:ff");

    // n0 sends VLAN 10
    Ptr<VlanSenderApp> vlanApp0 = CreateObject<VlanSenderApp>();
    vlanApp0->Setup(devices.Get(0)->GetIfIndex(), bcastMac, 10, 48);
    nodes.Get(0)->AddApplication(vlanApp0);
    vlanApp0->SetStartTime(Seconds(1.0));
    vlanApp0->SetStopTime(Seconds(8.0));

    // n1 also sends VLAN 10 (shows multiple senders on same VLAN)
    Ptr<VlanSenderApp> vlanApp1 = CreateObject<VlanSenderApp>();
    vlanApp1->Setup(devices.Get(1)->GetIfIndex(), bcastMac, 10, 48);
    nodes.Get(1)->AddApplication(vlanApp1);
    vlanApp1->SetStartTime(Seconds(1.5)); // slight offset
    vlanApp1->SetStopTime(Seconds(8.0));

    // n2 sends VLAN 20
    Ptr<VlanSenderApp> vlanApp2 = CreateObject<VlanSenderApp>();
    vlanApp2->Setup(devices.Get(2)->GetIfIndex(), bcastMac, 20, 48);
    nodes.Get(2)->AddApplication(vlanApp2);
    vlanApp2->SetStartTime(Seconds(1.0));
    vlanApp2->SetStopTime(Seconds(8.0));

    // n3 also sends VLAN 20
    Ptr<VlanSenderApp> vlanApp3 = CreateObject<VlanSenderApp>();
    vlanApp3->Setup(devices.Get(3)->GetIfIndex(), bcastMac, 20, 48);
    nodes.Get(3)->AddApplication(vlanApp3);
    vlanApp3->SetStartTime(Seconds(2.0)); // slight offset
    vlanApp3->SetStopTime(Seconds(8.0));

    if (g_pcapEnabled)
    {
        // Capture on all nodes (promiscuous) – all see all VLAN frames on shared bus
        std::string prefix = outDir + "vlan";
        csma.EnablePcap(prefix, devices, true);
        for (uint32_t i = 0; i < devices.GetN(); i++)
        {
            std::cout << "  PCAP (n" << i << "): " << PcapFilename(prefix, devices.Get(i)) << std::endl;
        }
        std::cout << "\n  Wireshark hints:" << std::endl;
        std::cout << "    Filter: vlan           → all 802.1Q frames" << std::endl;
        std::cout << "    Filter: vlan.id==10    → VLAN 10 only (n0, n1 senders)" << std::endl;
        std::cout << "    Filter: vlan.id==20    → VLAN 20 only (n2, n3 senders)" << std::endl;
        std::cout << "    Field:  eth.type       → must be 0x8100" << std::endl;
    }

    Simulator::Stop(Seconds(10.0));
    Simulator::Run();
    Simulator::Destroy();

    if (g_pcapEnabled)
    {
        std::cout << "  Verifying PCAP output..." << std::endl;
        VerifyAnyPcapInDir(outDir);
    }
}

// =============================================================================
// MAIN
// =============================================================================
int
main(int argc, char* argv[])
{
    // =========================================================================
    // GUIDANCE for [C] question: How to select and run scenarios
    // --scenario= selects which scenario to run.
    // --pcap=1   enables PCAP capture (required for Wireshark analysis).
    // --scenario=all runs all five scenarios sequentially.
    // =========================================================================
    std::string scenario = "ethernet-basic";
    int         pcap     = 0;
    int         verbose  = 0;

    CommandLine cmd(__FILE__);
    cmd.AddValue("scenario",
                 "Scenario to run: ethernet-basic | arp | switch-learning | crc | vlan | all",
                 scenario);
    cmd.AddValue("pcap", "Enable PCAP capture (0=off, 1=on)", pcap);
    cmd.AddValue("verbose", "Enable INFO-level ns-3 logging (0=off, 1=on)", verbose);
    cmd.Parse(argc, argv);

    g_pcapEnabled = (pcap == 1);

    if (verbose == 1)
    {
        LogComponentEnable("LinkLayerLab", LOG_LEVEL_INFO);
        LogComponentEnable("CsmaNetDevice", LOG_LEVEL_INFO);
        LogComponentEnable("BridgeNetDevice", LOG_LEVEL_INFO);
    }

    // Validate scenario name
    static const std::vector<std::string> validScenarios = {
        "ethernet-basic", "arp", "switch-learning", "crc", "vlan", "all"
    };
    bool valid = false;
    for (const auto& s : validScenarios)
    {
        if (scenario == s)
        {
            valid = true;
            break;
        }
    }
    if (!valid)
    {
        std::cerr << "ERROR: Unknown scenario '" << scenario << "'" << std::endl;
        std::cerr << "Valid: ethernet-basic | arp | switch-learning | crc | vlan | all" << std::endl;
        return 1;
    }

    // Create base output directory
    EnsureDirectory(g_baseDir);

    std::cout << "==========================================" << std::endl;
    std::cout << " ns-3 Lab 5: Link Layer and LANs" << std::endl;
    std::cout << "==========================================" << std::endl;
    std::cout << " Scenario : " << scenario << std::endl;
    std::cout << " PCAP     : " << (g_pcapEnabled ? "enabled" : "disabled (use --pcap=1)") << std::endl;
    std::cout << " Output   : " << g_baseDir << std::endl;
    std::cout << "==========================================" << std::endl;

    // Determine which scenarios to run
    bool runAll   = (scenario == "all");
    bool runEth   = runAll || (scenario == "ethernet-basic");
    bool runArp   = runAll || (scenario == "arp");
    bool runSw    = runAll || (scenario == "switch-learning");
    bool runCrc   = runAll || (scenario == "crc");
    bool runVlan  = runAll || (scenario == "vlan");

    if (runEth)
    {
        RunEthernetBasic(g_baseDir + "ethernet-basic/");
    }
    if (runArp)
    {
        RunArp(g_baseDir + "arp/");
    }
    if (runSw)
    {
        RunSwitchLearning(g_baseDir + "switch-learning/");
    }
    if (runCrc)
    {
        RunCrc(g_baseDir + "crc/");
    }
    if (runVlan)
    {
        RunVlan(g_baseDir + "vlan/");
    }

    std::cout << "\n==========================================" << std::endl;
    std::cout << " Simulation complete." << std::endl;
    std::cout << " Output directory: " << g_baseDir << std::endl;
    std::cout << "==========================================" << std::endl;

    if (!g_pcapEnabled)
    {
        std::cout << "\nNOTE: PCAP capture was NOT enabled." << std::endl;
        std::cout << "Re-run with --pcap=1 to generate .pcap files for Wireshark." << std::endl;
    }
    else
    {
        std::cout << "\nAll PCAP files are in: " << g_baseDir << std::endl;
        std::cout << "Open with: wireshark <filename>.pcap" << std::endl;
        std::cout << "\nKey Wireshark filters:" << std::endl;
        std::cout << "  eth.type == 0x0800     IPv4 frames" << std::endl;
        std::cout << "  eth.type == 0x0806     ARP frames" << std::endl;
        std::cout << "  eth.type == 0x8100     802.1Q VLAN frames" << std::endl;
        std::cout << "  arp.opcode == 1        ARP Request" << std::endl;
        std::cout << "  arp.opcode == 2        ARP Reply" << std::endl;
        std::cout << "  eth.dst == ff:ff:ff:ff:ff:ff  broadcast frames" << std::endl;
        std::cout << "  icmp                   ICMP traffic (ping)" << std::endl;
        std::cout << "  udp.port == 4000       UDP echo traffic (port 4000, NOT discard)" << std::endl;
        std::cout << "  vlan.id == 10          VLAN 10 frames" << std::endl;
        std::cout << "  vlan.id == 20          VLAN 20 frames" << std::endl;
    }

    return 0;
}
