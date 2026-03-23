/*
 * =============================================================================
 * ns-3 Wireshark Lab Simulation - IP
 * =============================================================================
 *
 * This script generates PCAP files for Wireshark IP lab exercises.
 * Based on Kurose & Ross "Computer Networking: A Top-Down Approach" labs v8.0.
 *
 * =============================================================================
 * HOW TO RUN EACH SCENARIO
 * =============================================================================
 *
 * Build:
 *   ./ns3 build
 *   (or specifically: ./ns3 build scratch_d0002e_lab3-with-guidance)
 *
 * Run scenarios (outputs go to "scratch/d0002e/lab 3 output/"):
 *
 * 1) BASIC IPv4 FORWARDING:
 *    ./ns3 run "scratch/d0002e/lab3 --scenario=basic-forwarding --pcap=1"
 *    PCAP: client-0-0.pcap, router*-0-0.pcap, server-0-0.pcap
 *    Shows: ICMP Echo Request/Reply traversing routers, TTL decrement
 *    Wireshark: Inspect IP header TTL field at each hop
 *
 * 2) IPv4 FRAGMENTATION:
 *    ./ns3 run "scratch/d0002e/lab3 --scenario=fragmentation --pcap=1"
 *    PCAP: client-0-0.pcap, router-*.pcap, server-0-0.pcap
 *    Shows: Large UDP datagram fragmented due to MTU constraints
 *    Wireshark: Filter "ip.flags.mf || ip.frag_offset > 0" for fragments
 *
 * 3) ROUTING AND FORWARDING:
 *    ./ns3 run "scratch/d0002e/lab3 --scenario=routing --pcap=1"
 *    PCAP: client-0-0.pcap, multiple router interfaces
 *    Shows: IP forwarding decisions based on routing tables
 *    Wireshark: Trace packet path through network
 *
 * 4) TTL EXPIRY (TRACEROUTE-STYLE):
 *    ./ns3 run "scratch/d0002e/lab3 --scenario=ttl-expiry --pcap=1"
 *    PCAP: client-0-0.pcap - Shows ICMP Time Exceeded messages
 *    Wireshark: Filter "icmp.type == 11" for TTL exceeded
 *
 * 5) ALL SCENARIOS:
 *    ./ns3 run "scratch/d0002e/lab3 --scenario=all --pcap=1"
 *    PCAP: Separate subfolder per scenario
 *
 * Additional options:
 *   --pcap=1            Enable PCAP capture (required for Wireshark analysis)
 *   --verbose=true      Enable detailed logging
 *   --packetSize=3500   UDP packet size for fragmentation (default: 3500)
 *   --mtu=1500          MTU size for fragmentation test (default: 1500)
 *
 * =============================================================================
 * NETWORK TOPOLOGY
 * =============================================================================
 *
 * Basic Forwarding / TTL Expiry Scenario (3 routers in chain):
 *
 *   +--------+     +----------+     +----------+     +----------+     +--------+
 *   | Source |     | Router 1 |     | Router 2 |     | Router 3 |     |  Dest  |
 *   |  (n0)  +-----+   (n1)   +-----+   (n2)   +-----+   (n3)   +-----+  (n4)  |
 *   |10.1.1.1|     |10.1.1.2  |     |10.1.2.2  |     |10.1.3.2  |     |10.1.4.2|
 *   +--------+     |10.1.2.1  |     |10.1.3.1  |     |10.1.4.1  |     +--------+
 *                  +----------+     +----------+     +----------+
 *
 *   Subnets: 10.1.1.0/24, 10.1.2.0/24, 10.1.3.0/24, 10.1.4.0/24
 *
 * Fragmentation Scenario:
 *
 *   +--------+      +-----------+      +--------+
 *   | Source |      | Router 1  |      |  Dest  |
 *   |  (n0)  +------+   (n1)    +------+  (n2)  |
 *   |10.1.1.1|      |10.1.1.2   |      |10.1.2.2|
 *   +--------+      |10.1.2.1   |      +--------+
 *   MTU=1500        +----+------+      MTU=1500
 *                   MTU=576 (small)
 *
 * Routing Scenario (multiple paths):
 *
 *                    +----------+
 *                    | Router 1 |
 *               +----+   (n1)   +----+
 *   +--------+  |    |10.1.2.1  |    |  +--------+
 *   | Source +--+    +----------+    +--+  Dest  |
 *   |  (n0)  |                          |  (n3)  |
 *   |10.1.1.1+--+    +----------+    +--+10.1.4.2|
 *   +--------+  |    | Router 2 |    |  +--------+
 *               +----+   (n2)   +----+
 *                    |10.1.3.1  |
 *                    +----------+
 *
 * =============================================================================
 * QUESTIONS REFERENCE
 * =============================================================================
 *
 * [V] = Wireshark analysis verified by textbook
 * [W] = Wireshark analysis (tables/graphs/screenshots/statistics)
 * [C] = Simulation code with explanation
 * [B] = Both Wireshark analysis and simulation code
 * [T] = Textbook description/explanation only
 *
 * =============================================================================
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/internet-apps-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"

#include <filesystem>
#include <fstream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("IpLab");

// =============================================================================
// Output directory (note: contains space as per requirement)
// =============================================================================
static std::string g_outputDir = "scratch/d0002e/lab 3 output/";

// =============================================================================
// Relevant to [C]: g_packetSize configures UDP datagram size for fragmentation
// Packets larger than MTU will be fragmented by the IP layer
// =============================================================================
static uint32_t g_packetSize = 3500;

// =============================================================================
// Relevant to [C]: g_mtu configures the Maximum Transmission Unit
// Used to demonstrate IP fragmentation when packet size > MTU
// =============================================================================
static uint32_t g_mtu = 1500;

// =============================================================================
// Relevant to [C]: g_pcapEnabled controls PCAP file generation
// Set via --pcap=1 command line argument
// =============================================================================
static bool g_pcapEnabled = false;

// =============================================================================
// PCAP VERIFICATION HELPER
// =============================================================================

bool VerifyPcapFile(const std::string& filepath)
{
    std::error_code ec;
    if (!std::filesystem::exists(filepath, ec))
    {
        std::cerr << "ERROR: PCAP file not found: " << filepath << std::endl;
        return false;
    }

    auto fileSize = std::filesystem::file_size(filepath, ec);
    if (ec || fileSize == 0)
    {
        std::cerr << "ERROR: PCAP file is empty: " << filepath << std::endl;
        return false;
    }

    std::cout << "OK: generated " << filepath << " (" << fileSize << " bytes)" << std::endl;
    return true;
}

// =============================================================================
// BASIC IPv4 FORWARDING SCENARIO
// =============================================================================
// Relevant to [V]: Demonstrates IP datagram forwarding through routers
// TTL (Time To Live) decrements by 1 at each router hop (Section 4.3.1)
//
// Relevant to [W]: Capture at each router interface shows:
//   - Same source/destination IP addresses throughout
//   - TTL decreasing by 1 at each hop
//   - Different source/destination MAC addresses at each link
//
// Relevant to [C]: Ipv4GlobalRoutingHelper::PopulateRoutingTables() creates
// routing entries automatically based on network topology
// =============================================================================

void RunBasicForwardingScenario(const std::string& outputPath)
{
    NS_LOG_INFO("=== Running Basic IPv4 Forwarding Scenario ===");
    NS_LOG_INFO("This scenario demonstrates IP datagram forwarding through routers.");
    NS_LOG_INFO("Open PCAPs in Wireshark to observe TTL decrement at each hop.");

    // =============================================================================
    // Relevant to [C]: Create Network Nodes
    // n0: Source host
    // n1, n2, n3: Routers
    // n4: Destination host
    // =============================================================================

    NodeContainer allNodes;
    allNodes.Create(5);

    Ptr<Node> source = allNodes.Get(0);
    Ptr<Node> router1 = allNodes.Get(1);
    Ptr<Node> router2 = allNodes.Get(2);
    Ptr<Node> router3 = allNodes.Get(3);
    Ptr<Node> dest = allNodes.Get(4);

    // =============================================================================
    // Relevant to [C]: Point-to-Point Links Between Nodes
    // Each link represents a separate IP subnet
    // The 2ms delay affects round-trip time for ICMP Echo
    // =============================================================================

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("2ms"));

    // Link 1: Source <-> Router1 (10.1.1.0/24)
    NetDeviceContainer devicesSourceR1 = p2p.Install(source, router1);

    // Link 2: Router1 <-> Router2 (10.1.2.0/24)
    NetDeviceContainer devicesR1R2 = p2p.Install(router1, router2);

    // Link 3: Router2 <-> Router3 (10.1.3.0/24)
    NetDeviceContainer devicesR2R3 = p2p.Install(router2, router3);

    // Link 4: Router3 <-> Dest (10.1.4.0/24)
    NetDeviceContainer devicesR3Dest = p2p.Install(router3, dest);

    // =============================================================================
    // Relevant to [C]: Internet Stack Installation
    // InternetStackHelper installs IPv4, IPv6, UDP, TCP, and ICMP protocols
    // Routers automatically forward packets between their interfaces
    // =============================================================================

    InternetStackHelper internet;
    internet.Install(allNodes);

    // =============================================================================
    // Relevant to [C]: IP Address Assignment
    // Ipv4AddressHelper assigns addresses from specified subnets
    // Each point-to-point link is a separate subnet
    //
    // Relevant to [B]: These addresses are visible in Wireshark:
    //   - Source IP: 10.1.1.1
    //   - Destination IP: 10.1.4.2
    //   - Router interfaces have addresses on each connected subnet
    // =============================================================================

    Ipv4AddressHelper address;

    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer ifSourceR1 = address.Assign(devicesSourceR1);

    address.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer ifR1R2 = address.Assign(devicesR1R2);

    address.SetBase("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer ifR2R3 = address.Assign(devicesR2R3);

    address.SetBase("10.1.4.0", "255.255.255.0");
    Ipv4InterfaceContainer ifR3Dest = address.Assign(devicesR3Dest);

    // =============================================================================
    // Relevant to [C]: Global Routing Configuration
    // PopulateRoutingTables() builds routing tables for all nodes automatically
    // Each router learns paths to all subnets in the network
    //
    // Relevant to [T]: This simulates distance-vector or link-state routing
    // protocols converging to a stable state (Section 5.2, 5.3)
    // =============================================================================

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // =============================================================================
    // Relevant to [C]: ICMP Echo (Ping) Application
    // PingHelper creates ICMP Echo Request packets to destination
    // Destination's ICMP stack automatically replies with Echo Reply
    //
    // Relevant to [V]: TTL field in IP header (Section 4.3.1):
    //   - Initial TTL set by source (typically 64)
    //   - Each router decrements TTL by 1
    //   - If TTL reaches 0, router drops packet and sends ICMP Time Exceeded
    // =============================================================================

    // Create ping application on source
    PingHelper pingHelper(ifR3Dest.GetAddress(1)); // Dest IP: 10.1.4.2
    pingHelper.SetAttribute("Interval", TimeValue(Seconds(1.0)));
    pingHelper.SetAttribute("Size", UintegerValue(56)); // Standard ping size
    pingHelper.SetAttribute("VerboseMode", EnumValue(Ping::VERBOSE));
    ApplicationContainer pingApps = pingHelper.Install(source);
    pingApps.Start(Seconds(1.0));
    pingApps.Stop(Seconds(10.0));

    // =============================================================================
    // Relevant to [W]: PCAP Capture Points
    // Capturing at each link shows the packet traversing the network
    // Compare TTL values at each capture point to see decrement
    //
    // Wireshark analysis:
    //   1. Filter: "icmp"
    //   2. Compare IP.TTL field across captures at different routers
    //   3. Note: Source/Dest IP remain constant, MAC addresses change
    // =============================================================================

    if (g_pcapEnabled)
    {
        p2p.EnablePcap(outputPath + "client", devicesSourceR1.Get(0), true);
        p2p.EnablePcap(outputPath + "router1-to-client", devicesSourceR1.Get(1), true);
        p2p.EnablePcap(outputPath + "router1-to-r2", devicesR1R2.Get(0), true);
        p2p.EnablePcap(outputPath + "router2-to-r1", devicesR1R2.Get(1), true);
        p2p.EnablePcap(outputPath + "router2-to-r3", devicesR2R3.Get(0), true);
        p2p.EnablePcap(outputPath + "router3-to-r2", devicesR2R3.Get(1), true);
        p2p.EnablePcap(outputPath + "router3-to-server", devicesR3Dest.Get(0), true);
        p2p.EnablePcap(outputPath + "server", devicesR3Dest.Get(1), true);
    }

    Simulator::Stop(Seconds(12.0));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("Basic IPv4 Forwarding scenario complete.");
    NS_LOG_INFO("Hint: Compare TTL values in client.pcap vs server.pcap (should differ by 3)");
}

// =============================================================================
// IPv4 FRAGMENTATION SCENARIO
// =============================================================================
// Relevant to [V]: IP fragmentation occurs when datagram size > link MTU
// (Section 4.3.1)
//
// Relevant to [W]: Fragmentation visible in Wireshark via:
//   - IP Flags: MF (More Fragments) bit set on all but last fragment
//   - Fragment Offset: Non-zero for subsequent fragments
//   - Total Length: Each fragment has smaller total length
//
// Relevant to [B]: Fragment Identification field is same across all fragments
// This allows receiver to reassemble the original datagram
//
// Relevant to [C]: Fragmentation is handled by IP layer automatically
// Application sends large datagram, IP layer fragments if needed
// =============================================================================

void RunFragmentationScenario(const std::string& outputPath)
{
    NS_LOG_INFO("=== Running IPv4 Fragmentation Scenario ===");
    NS_LOG_INFO("This scenario demonstrates IP fragmentation due to MTU constraints.");
    NS_LOG_INFO("Open source.pcap in Wireshark to see fragments.");

    NodeContainer nodes;
    nodes.Create(3);

    Ptr<Node> source = nodes.Get(0);
    Ptr<Node> router = nodes.Get(1);
    Ptr<Node> dest = nodes.Get(2);

    // =============================================================================
    // Relevant to [C]: Link with Large MTU (Source to Router)
    // This link can carry the full packet without fragmentation
    // =============================================================================

    PointToPointHelper p2pLarge;
    p2pLarge.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2pLarge.SetChannelAttribute("Delay", StringValue("2ms"));
    p2pLarge.SetDeviceAttribute("Mtu", UintegerValue(g_mtu)); // 1500 bytes

    NetDeviceContainer devicesSourceRouter = p2pLarge.Install(source, router);

    // =============================================================================
    // Relevant to [C]: Link with Small MTU (Router to Dest)
    // This link has MTU=576, forcing fragmentation of larger packets
    //
    // Relevant to [V]: MTU 576 is the minimum MTU guaranteed for IPv4 (RFC 791)
    // Fragmentation occurs when IP datagram exceeds this MTU
    // =============================================================================

    PointToPointHelper p2pSmall;
    p2pSmall.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2pSmall.SetChannelAttribute("Delay", StringValue("2ms"));
    p2pSmall.SetDeviceAttribute("Mtu", UintegerValue(576)); // Small MTU forces fragmentation

    NetDeviceContainer devicesRouterDest = p2pSmall.Install(router, dest);

    InternetStackHelper internet;
    internet.Install(nodes);

    Ipv4AddressHelper address;

    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer ifSourceRouter = address.Assign(devicesSourceRouter);

    address.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer ifRouterDest = address.Assign(devicesRouterDest);

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // =============================================================================
    // Relevant to [C]: UDP Server Setup
    // PacketSink receives UDP datagrams (including reassembled fragments)
    // =============================================================================

    uint16_t serverPort = 5001;
    Address serverAddress(InetSocketAddress(ifRouterDest.GetAddress(1), serverPort));
    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory",
                                 InetSocketAddress(Ipv4Address::GetAny(), serverPort));
    ApplicationContainer serverApp = sinkHelper.Install(dest);
    serverApp.Start(Seconds(0.0));
    serverApp.Stop(Seconds(30.0));

    // =============================================================================
    // Relevant to [C]: UDP Client Sending Large Datagram
    // OnOffApplication sends packets of g_packetSize bytes (default: 3500)
    // This exceeds MTU 576, so IP layer will fragment the datagram
    //
    // Relevant to [V]: Fragment calculation (Section 4.3.1):
    //   - Maximum IP payload per fragment = MTU - 20 (IP header) = 556 bytes
    //   - Fragment offset must be multiple of 8 bytes, so max payload = 552
    //   - Number of fragments = ceil(original_payload / 552)
    //
    // Relevant to [B]: Original IP datagram:
    //   - IP Header: 20 bytes
    //   - UDP Header: 8 bytes
    //   - UDP Payload: g_packetSize bytes
    //   - Total: 20 + 8 + g_packetSize
    //
    // Each fragment has:
    //   - IP Header: 20 bytes (with fragment offset and MF flag)
    //   - Fragment payload: up to 552 bytes
    // =============================================================================

    OnOffHelper clientHelper("ns3::UdpSocketFactory", serverAddress);
    clientHelper.SetAttribute("DataRate", StringValue("500kbps"));
    clientHelper.SetAttribute("PacketSize", UintegerValue(g_packetSize));
    clientHelper.SetAttribute("MaxBytes", UintegerValue(g_packetSize * 5)); // Send 5 large packets

    ApplicationContainer clientApp = clientHelper.Install(source);
    clientApp.Start(Seconds(1.0));
    clientApp.Stop(Seconds(29.0));

    // =============================================================================
    // Relevant to [W]: PCAP Analysis for Fragmentation
    // In Wireshark:
    //   1. Filter: "ip.flags.mf == 1 || ip.frag_offset > 0" for fragments
    //   2. Check IP header fields:
    //      - Identification: Same across fragments of same datagram
    //      - Flags: MF=1 for all except last fragment
    //      - Fragment Offset: Increments by (fragment_payload_size / 8)
    //   3. First fragment contains UDP header, subsequent fragments don't
    // =============================================================================

    if (g_pcapEnabled)
    {
        p2pLarge.EnablePcap(outputPath + "client", devicesSourceRouter.Get(0), true);
        p2pLarge.EnablePcap(outputPath + "router-from-client", devicesSourceRouter.Get(1), true);
        p2pSmall.EnablePcap(outputPath + "router-to-server", devicesRouterDest.Get(0), true);
        p2pSmall.EnablePcap(outputPath + "server", devicesRouterDest.Get(1), true);
    }

    Simulator::Stop(Seconds(32.0));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("IPv4 Fragmentation scenario complete.");
    NS_LOG_INFO("Packet size: " << g_packetSize << " bytes");
    NS_LOG_INFO("Small link MTU: 576 bytes");
    NS_LOG_INFO("Expected fragments per packet: ~" << ((g_packetSize + 8) / 552 + 1));
    NS_LOG_INFO("Hint: Filter 'ip.flags.mf == 1 || ip.frag_offset > 0' in Wireshark");
}

// =============================================================================
// ROUTING AND FORWARDING SCENARIO
// =============================================================================
// Relevant to [V]: Each router makes independent forwarding decision
// based on destination IP address and routing table (Section 4.1)
//
// Relevant to [W]: Observe packet path through network by comparing
// capture points at different router interfaces
//
// Relevant to [C]: Global routing builds shortest-path routes automatically
// Different destination IPs may take different paths through the network
// =============================================================================

void RunRoutingScenario(const std::string& outputPath)
{
    NS_LOG_INFO("=== Running Routing and Forwarding Scenario ===");
    NS_LOG_INFO("This scenario demonstrates IP routing decisions.");
    NS_LOG_INFO("Open PCAPs to trace packet path through the network.");

    // =============================================================================
    // Relevant to [C]: Network with Multiple Routers
    // This topology has two potential paths from source to destination
    // Global routing will choose the shortest path
    // =============================================================================

    NodeContainer nodes;
    nodes.Create(4);

    Ptr<Node> source = nodes.Get(0);
    Ptr<Node> router1 = nodes.Get(1);
    Ptr<Node> router2 = nodes.Get(2);
    Ptr<Node> dest = nodes.Get(3);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("2ms"));

    // =============================================================================
    // Relevant to [C]: Network Links
    // Source connects to both routers
    // Both routers connect to destination
    // Creates redundant paths through the network
    // =============================================================================

    // Source <-> Router1 (10.1.1.0/24)
    NetDeviceContainer devicesSourceR1 = p2p.Install(source, router1);

    // Source <-> Router2 (10.1.2.0/24)
    NetDeviceContainer devicesSourceR2 = p2p.Install(source, router2);

    // Router1 <-> Dest (10.1.3.0/24)
    NetDeviceContainer devicesR1Dest = p2p.Install(router1, dest);

    // Router2 <-> Dest (10.1.4.0/24)
    NetDeviceContainer devicesR2Dest = p2p.Install(router2, dest);

    InternetStackHelper internet;
    internet.Install(nodes);

    Ipv4AddressHelper address;

    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer ifSourceR1 = address.Assign(devicesSourceR1);

    address.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer ifSourceR2 = address.Assign(devicesSourceR2);

    address.SetBase("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer ifR1Dest = address.Assign(devicesR1Dest);

    address.SetBase("10.1.4.0", "255.255.255.0");
    Ipv4InterfaceContainer ifR2Dest = address.Assign(devicesR2Dest);

    // =============================================================================
    // Relevant to [C]: Routing Table Construction
    // PopulateRoutingTables() builds routes using shortest path first algorithm
    // Each node gets routes to reach all subnets
    //
    // Relevant to [B]: Routing decision is based on:
    //   - Destination IP address in packet header
    //   - Longest prefix match in routing table
    //   - Next-hop router determined from matching route
    // =============================================================================

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // =============================================================================
    // Relevant to [W]: Print Routing Tables
    // Shows the routing entries for each node
    // =============================================================================

    NS_LOG_INFO("=== Routing Tables ===");
    Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper>(&std::cout);
    Ipv4GlobalRoutingHelper::PrintRoutingTableAllAt(Seconds(0.5), routingStream);

    // Save routing tables to file
    std::ofstream routingFile(outputPath + "routing-tables.txt");
    Ptr<OutputStreamWrapper> fileStream = Create<OutputStreamWrapper>(&routingFile);
    Ipv4GlobalRoutingHelper::PrintRoutingTableAllAt(Seconds(0.5), fileStream);

    // =============================================================================
    // Relevant to [C]: Ping Application to Test Routing
    // Sends ICMP Echo Request to destination IP
    // Routing decision at source determines which path packet takes
    // =============================================================================

    // Ping to destination via one of the paths
    PingHelper pingHelper(ifR1Dest.GetAddress(1)); // Dest: 10.1.3.2
    pingHelper.SetAttribute("Interval", TimeValue(Seconds(1.0)));
    pingHelper.SetAttribute("Size", UintegerValue(56));
    pingHelper.SetAttribute("VerboseMode", EnumValue(Ping::VERBOSE));
    ApplicationContainer pingApps = pingHelper.Install(source);
    pingApps.Start(Seconds(1.0));
    pingApps.Stop(Seconds(10.0));

    // =============================================================================
    // Relevant to [W]: PCAP Capture at All Interfaces
    // By checking which capture shows the packet, we can determine the route
    // Packets should appear only on the chosen path
    // =============================================================================

    if (g_pcapEnabled)
    {
        p2p.EnablePcap(outputPath + "client-to-r1", devicesSourceR1.Get(0), true);
        p2p.EnablePcap(outputPath + "client-to-r2", devicesSourceR2.Get(0), true);
        p2p.EnablePcap(outputPath + "router1-from-client", devicesSourceR1.Get(1), true);
        p2p.EnablePcap(outputPath + "router2-from-client", devicesSourceR2.Get(1), true);
        p2p.EnablePcap(outputPath + "router1-to-server", devicesR1Dest.Get(0), true);
        p2p.EnablePcap(outputPath + "router2-to-server", devicesR2Dest.Get(0), true);
        p2p.EnablePcap(outputPath + "server-from-r1", devicesR1Dest.Get(1), true);
        p2p.EnablePcap(outputPath + "server-from-r2", devicesR2Dest.Get(1), true);
    }

    Simulator::Stop(Seconds(12.0));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("Routing and Forwarding scenario complete.");
    NS_LOG_INFO("Routing tables saved to: " << outputPath << "routing-tables.txt");
    NS_LOG_INFO("Hint: Check which interface PCAPs contain ICMP traffic");
}

// =============================================================================
// TTL EXPIRY SCENARIO (TRACEROUTE-STYLE)
// =============================================================================
// Relevant to [V]: When TTL reaches 0, router drops packet and sends
// ICMP Time Exceeded message back to source (Section 4.3.1)
//
// Relevant to [W]: ICMP Type 11 (Time Exceeded) messages visible
// Filter: "icmp.type == 11"
//
// Relevant to [C]: Traceroute uses incrementing TTL values to discover
// each hop on the path to destination
// =============================================================================

void RunTtlExpiryScenario(const std::string& outputPath)
{
    NS_LOG_INFO("=== Running TTL Expiry Scenario ===");
    NS_LOG_INFO("This scenario demonstrates TTL expiry and ICMP Time Exceeded.");
    NS_LOG_INFO("Open source.pcap in Wireshark to see ICMP error messages.");

    // Create same topology as basic forwarding
    NodeContainer allNodes;
    allNodes.Create(5);

    Ptr<Node> source = allNodes.Get(0);
    Ptr<Node> router1 = allNodes.Get(1);
    Ptr<Node> router2 = allNodes.Get(2);
    Ptr<Node> router3 = allNodes.Get(3);
    Ptr<Node> dest = allNodes.Get(4);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("2ms"));

    NetDeviceContainer devicesSourceR1 = p2p.Install(source, router1);
    NetDeviceContainer devicesR1R2 = p2p.Install(router1, router2);
    NetDeviceContainer devicesR2R3 = p2p.Install(router2, router3);
    NetDeviceContainer devicesR3Dest = p2p.Install(router3, dest);

    InternetStackHelper internet;
    internet.Install(allNodes);

    Ipv4AddressHelper address;

    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer ifSourceR1 = address.Assign(devicesSourceR1);

    address.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer ifR1R2 = address.Assign(devicesR1R2);

    address.SetBase("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer ifR2R3 = address.Assign(devicesR2R3);

    address.SetBase("10.1.4.0", "255.255.255.0");
    Ipv4InterfaceContainer ifR3Dest = address.Assign(devicesR3Dest);

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // =============================================================================
    // Relevant to [C]: Sending UDP Packets with Low TTL
    // We'll create a raw socket application that sends packets with specific TTL
    // This simulates traceroute behavior
    // =============================================================================

    uint16_t serverPort = 5001;

    // UDP Server at destination (won't receive packets with low TTL)
    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory",
                                 InetSocketAddress(Ipv4Address::GetAny(), serverPort));
    ApplicationContainer serverApp = sinkHelper.Install(dest);
    serverApp.Start(Seconds(0.0));
    serverApp.Stop(Seconds(30.0));

    // =============================================================================
    // Relevant to [C]: Custom TTL Configuration
    // We configure the socket's TTL attribute to create low-TTL packets
    // Each packet with TTL=1 will expire at the first router
    // TTL=2 expires at second router, etc.
    //
    // Relevant to [V]: ICMP Time Exceeded (Type 11, Code 0)
    //   - Sent by router when TTL reaches 0
    //   - Contains IP header + first 8 bytes of original datagram
    //   - Source of ICMP message identifies the router
    // =============================================================================

    // Send packets with TTL=1 (expires at router1)
    Ptr<Socket> socket1 = Socket::CreateSocket(source, UdpSocketFactory::GetTypeId());
    socket1->SetIpTtl(1);
    InetSocketAddress destAddr(ifR3Dest.GetAddress(1), serverPort);

    Simulator::Schedule(Seconds(1.0), [socket1, destAddr]() {
        socket1->Connect(destAddr);
        Ptr<Packet> packet = Create<Packet>(64);
        socket1->Send(packet);
        NS_LOG_INFO("Sent packet with TTL=1 (should expire at Router1)");
    });

    // Send packets with TTL=2 (expires at router2)
    Ptr<Socket> socket2 = Socket::CreateSocket(source, UdpSocketFactory::GetTypeId());
    socket2->SetIpTtl(2);

    Simulator::Schedule(Seconds(2.0), [socket2, destAddr]() {
        socket2->Connect(destAddr);
        Ptr<Packet> packet = Create<Packet>(64);
        socket2->Send(packet);
        NS_LOG_INFO("Sent packet with TTL=2 (should expire at Router2)");
    });

    // Send packets with TTL=3 (expires at router3)
    Ptr<Socket> socket3 = Socket::CreateSocket(source, UdpSocketFactory::GetTypeId());
    socket3->SetIpTtl(3);

    Simulator::Schedule(Seconds(3.0), [socket3, destAddr]() {
        socket3->Connect(destAddr);
        Ptr<Packet> packet = Create<Packet>(64);
        socket3->Send(packet);
        NS_LOG_INFO("Sent packet with TTL=3 (should expire at Router3)");
    });

    // Send packets with TTL=4 (should reach destination)
    Ptr<Socket> socket4 = Socket::CreateSocket(source, UdpSocketFactory::GetTypeId());
    socket4->SetIpTtl(4);

    Simulator::Schedule(Seconds(4.0), [socket4, destAddr]() {
        socket4->Connect(destAddr);
        Ptr<Packet> packet = Create<Packet>(64);
        socket4->Send(packet);
        NS_LOG_INFO("Sent packet with TTL=4 (should reach destination)");
    });

    // =============================================================================
    // Relevant to [W]: PCAP Analysis for TTL Expiry
    // In Wireshark:
    //   1. Filter: "icmp.type == 11" for Time Exceeded messages
    //   2. Each ICMP error has a different source IP (the router that dropped it)
    //   3. The embedded original IP header shows the low TTL value
    // =============================================================================

    if (g_pcapEnabled)
    {
        p2p.EnablePcap(outputPath + "client", devicesSourceR1.Get(0), true);
        p2p.EnablePcap(outputPath + "router1", devicesSourceR1.Get(1), true);
        p2p.EnablePcap(outputPath + "router2", devicesR1R2.Get(1), true);
        p2p.EnablePcap(outputPath + "router3", devicesR2R3.Get(1), true);
        p2p.EnablePcap(outputPath + "server", devicesR3Dest.Get(1), true);
    }

    Simulator::Stop(Seconds(10.0));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("TTL Expiry scenario complete.");
    NS_LOG_INFO("Hint: Filter 'icmp.type == 11' in Wireshark to see Time Exceeded");
    NS_LOG_INFO("Hint: Each ICMP error source IP identifies a router on the path");
}

// =============================================================================
// MAIN FUNCTION
// =============================================================================

int main(int argc, char* argv[])
{
    std::string scenario = "all";
    bool verbose = false;
    int pcap = 0;

    // =============================================================================
    // Relevant to [C]: Command-line argument parsing
    // --scenario selects which scenario to run
    // --pcap=1 enables PCAP capture for Wireshark analysis
    // =============================================================================

    CommandLine cmd(__FILE__);
    cmd.AddValue("scenario", "Scenario: basic-forwarding, fragmentation, routing, "
                             "ttl-expiry, all", scenario);
    cmd.AddValue("pcap", "Enable PCAP capture (0 or 1)", pcap);
    cmd.AddValue("verbose", "Enable verbose logging", verbose);
    cmd.AddValue("packetSize", "UDP packet size for fragmentation", g_packetSize);
    cmd.AddValue("mtu", "MTU size for source link", g_mtu);
    cmd.Parse(argc, argv);

    g_pcapEnabled = (pcap == 1);

    if (verbose)
    {
        LogComponentEnable("IpLab", LOG_LEVEL_INFO);
        LogComponentEnable("V4Ping", LOG_LEVEL_INFO);
        LogComponentEnable("Ipv4L3Protocol", LOG_LEVEL_INFO);
    }

    // Validate scenario
    std::vector<std::string> validScenarios = {
        "basic-forwarding", "fragmentation", "routing", "ttl-expiry", "all"
    };
    bool validScenario = false;
    for (const auto& s : validScenarios)
    {
        if (scenario == s)
        {
            validScenario = true;
            break;
        }
    }
    if (!validScenario)
    {
        std::cerr << "Invalid scenario: " << scenario << std::endl;
        std::cerr << "Valid scenarios: basic-forwarding, fragmentation, routing, "
                     "ttl-expiry, all" << std::endl;
        return 1;
    }

    std::cout << "=== ns-3 IP Lab ===" << std::endl;
    std::cout << "Scenario: " << scenario << std::endl;
    std::cout << "PCAP enabled: " << (g_pcapEnabled ? "yes" : "no") << std::endl;

    if (!g_pcapEnabled)
    {
        std::cout << "Note: Use --pcap=1 to enable PCAP capture for Wireshark analysis" << std::endl;
    }

    // Create output directory
    std::error_code ec;
    std::filesystem::create_directories(g_outputDir, ec);
    if (ec)
    {
        std::cerr << "Failed to create output directory: " << g_outputDir << std::endl;
        return 1;
    }

    bool success = true;

    // =============================================================================
    // Run scenarios
    // For --scenario=all, create subfolders to prevent overwriting
    // =============================================================================

    if (scenario == "basic-forwarding" || scenario == "all")
    {
        std::string outputPath = g_outputDir;
        if (scenario == "all")
        {
            outputPath = g_outputDir + "basic-forwarding/";
            std::filesystem::create_directories(outputPath, ec);
        }
        RunBasicForwardingScenario(outputPath);
        if (g_pcapEnabled)
        {
            success = success && VerifyPcapFile(outputPath + "client-0-0.pcap");
        }
    }

    if (scenario == "fragmentation" || scenario == "all")
    {
        std::string outputPath = g_outputDir;
        if (scenario == "all")
        {
            outputPath = g_outputDir + "fragmentation/";
            std::filesystem::create_directories(outputPath, ec);
        }
        RunFragmentationScenario(outputPath);
        if (g_pcapEnabled)
        {
            success = success && VerifyPcapFile(outputPath + "client-0-0.pcap");
        }
    }

    if (scenario == "routing" || scenario == "all")
    {
        std::string outputPath = g_outputDir;
        if (scenario == "all")
        {
            outputPath = g_outputDir + "routing/";
            std::filesystem::create_directories(outputPath, ec);
        }
        RunRoutingScenario(outputPath);
        if (g_pcapEnabled)
        {
            success = success && VerifyPcapFile(outputPath + "client-to-r1-0-0.pcap");
        }
    }

    if (scenario == "ttl-expiry" || scenario == "all")
    {
        std::string outputPath = g_outputDir;
        if (scenario == "all")
        {
            outputPath = g_outputDir + "ttl-expiry/";
            std::filesystem::create_directories(outputPath, ec);
        }
        RunTtlExpiryScenario(outputPath);
        if (g_pcapEnabled)
        {
            success = success && VerifyPcapFile(outputPath + "client-0-0.pcap");
        }
    }

    std::cout << std::endl;
    std::cout << "=== Simulation Complete ===" << std::endl;
    std::cout << "Output directory: " << g_outputDir << std::endl;

    if (scenario == "all")
    {
        std::cout << "Subfolders created for each scenario." << std::endl;
    }

    std::cout << std::endl;
    std::cout << "=== Analysis Hints ===" << std::endl;
    std::cout << "- Basic Forwarding: Compare TTL at client vs server (decrement per hop)" << std::endl;
    std::cout << "- Fragmentation: Filter 'ip.flags.mf == 1 || ip.frag_offset > 0'" << std::endl;
    std::cout << "- Routing: Check which interface PCAPs contain traffic" << std::endl;
    std::cout << "- TTL Expiry: Filter 'icmp.type == 11' for Time Exceeded" << std::endl;

    if (!g_pcapEnabled)
    {
        std::cout << std::endl;
        std::cout << "WARNING: PCAP capture was disabled. Use --pcap=1 for Wireshark analysis." << std::endl;
    }
    else if (!success)
    {
        std::cerr << "ERROR: One or more PCAP files failed verification!" << std::endl;
        return 1;
    }

    return 0;
}
