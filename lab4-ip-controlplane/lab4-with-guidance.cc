/*
 * =============================================================================
 * ns-3 Wireshark Lab Simulation - Routing Algorithms (Link State & Distance Vector)
 * =============================================================================
 *
 * Lab 4: Network Layer - Routing Algorithms (Chapter 5)
 *
 * This script generates PCAP files for Wireshark routing lab exercises.
 * Based on Kurose & Ross "Computer Networking: A Top-Down Approach" labs v8.0.
 *
 * =============================================================================
 * LEARNING GOALS
 * =============================================================================
 *
 * This lab covers:
 * - Link State (LS) vs Distance Vector (DV) routing algorithms
 * - OSPF-like Link State Advertisement (LSA) flooding behavior
 * - TTL field behavior and ICMP Time Exceeded generation
 * - Routing table convergence after link failures
 *
 * =============================================================================
 * EXAMPLE SCRIPTS USED AS BASIS
 * =============================================================================
 *
 * This script is based on the following ns-3 example scripts:
 *
 * 1. examples/routing/rip-simple-network.cc
 *    - Used for: RIP (Distance Vector) routing setup, link failure scheduling,
 *      RipHelper configuration, interface metric setting
 *    - Why: Demonstrates ns-3's RIP implementation with realistic topology
 *
 * 2. examples/routing/dynamic-global-routing.cc
 *    - Used for: Global routing with interface up/down events, route recomputation
 *    - Why: Shows how Ipv4GlobalRouting responds to topology changes
 *
 * 3. src/internet-apps/examples/ping.cc (pattern)
 *    - Used for: ICMP ping application setup
 *    - Why: Standard pattern for generating ICMP traffic
 *
 * =============================================================================
 * HOW TO RUN EACH SCENARIO
 * =============================================================================
 *
 * Build:
 *   ./ns3 build
 *
 * Run scenarios (outputs go to "scratch/d0002e/lab 4 output/" at ns-3.46.1 level):
 *
 * 1) LINK STATE vs DISTANCE VECTOR (LS/DV Comparison):
 *    ./ns3 run "scratch/d0002e/lab4-with-guidance --scenario=lsdv --pcap=1"
 *    PCAP: files under lab 4 output/lsdv/
 *    Shows: RIP updates (DV) and GlobalRouting (LS-like) behavior
 *    Wireshark: Filter "rip" for RIP updates, observe TTL changes
 *
 * 2) OSPF-LIKE LINK STATE ADVERTISEMENTS:
 *    ./ns3 run "scratch/d0002e/lab4-with-guidance --scenario=ospf-like --pcap=1"
 *    PCAP: files under lab 4 output/ospf-like/
 *    Shows: Periodic LSA messages flooded between routers
 *    Wireshark: Filter "udp.port==50001" for LSA packets
 *
 * 3) TTL AND ICMP TIME EXCEEDED:
 *    ./ns3 run "scratch/d0002e/lab4-with-guidance --scenario=ttl-icmp --pcap=1"
 *    PCAP: files under lab 4 output/ttl-icmp/
 *    Shows: ICMP Time Exceeded (Type 11) when TTL expires
 *    Wireshark: Filter "icmp.type==11" for Time Exceeded
 *
 * Additional options:
 *   --pcap=1           Enable PCAP capture (required for Wireshark analysis)
 *   --verbose=true     Enable detailed logging
 *   --mode=ls          For lsdv scenario: use Link State mode (default)
 *   --mode=dv          For lsdv scenario: use Distance Vector mode
 *
 * =============================================================================
 * NETWORK TOPOLOGY (LSDV and OSPF-like scenarios)
 * =============================================================================
 *
 *                 10.1.2.0/24         10.1.6.0/24
 *        [SRC]---[R1]---[R2]----------------[R4]---[DST]
 *                  \      |                  /
 *            10.1.3.0/24  |          10.1.5.0/24 (higher metric)
 *                    \    | 10.1.4.0/24     /
 *                     \   |                 /
 *                      +--[R3]-------------+
 *
 *   Preferred path before failure: SRC->R1->R2->R4->DST
 *   Backup path after failure:     SRC->R1->R3->R4->DST
 *   Link R2-R4 will fail at t=40s to demonstrate convergence
 *
 * =============================================================================
 * TTL-ICMP SCENARIO TOPOLOGY
 * =============================================================================
 *
 *   [SRC]----[R1]----[R2]----[R3]----[DST]
 *     |                               |
 *   10.1.1.1                      10.1.4.2
 *
 *   4 hops from SRC to DST
 *   Packets with TTL=1,2,3 will expire at R1,R2,R3 respectively
 *
 * =============================================================================
 * PORT SELECTION WARNING
 * =============================================================================
 *
 * IMPORTANT: We use ports 50000+ for all application traffic to avoid
 * Wireshark decoding packets as "DISCARD" protocol.
 *
 * Port 9 is the well-known DISCARD service port (RFC 863). If you use port 9,
 * Wireshark will show Protocol=DISCARD and Info=Discard, making analysis
 * confusing. Always use high-numbered ports (50000+) for lab exercises.
 *
 * To verify correct port usage in Wireshark:
 *   - Check that Protocol column does NOT show "DISCARD"
 *   - UDP/TCP port numbers should show your chosen port (e.g., 50001)
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
#include "ns3/csma-module.h"
#include "ns3/internet-apps-module.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-routing-table-entry.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"

#include <filesystem>
#include <fstream>
#include <sstream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("RoutingLab");

// =============================================================================
// OUTPUT DIRECTORY CONFIGURATION
// =============================================================================
// Output directory is at ns-3.46.1 level (NOT inside scratch)
// This matches the lab document requirement for "lab 4 output"
// =============================================================================
static std::string g_outputDir = "scratch/d0002e/lab 4 output/";

// =============================================================================
// PORT CONFIGURATION - AVOID PORT 9 (DISCARD)
// =============================================================================
// Guidance for [C] questions: These ports are used for application traffic.
// Port 50001 is used for LSA messages in OSPF-like scenario.
// Port 50002 is used for data traffic.
// We explicitly avoid port 9 to prevent Wireshark DISCARD decoding.
// =============================================================================
static const uint16_t LSA_PORT = 50001;
static const uint16_t DATA_PORT = 50002;

// =============================================================================
// PCAP ENABLED FLAG
// =============================================================================
static bool g_pcapEnabled = false;

// =============================================================================
// HELPER: Create output directory
// =============================================================================
void EnsureDirectory(const std::string& path)
{
    std::error_code ec;
    std::filesystem::create_directories(path, ec);
    if (ec)
    {
        NS_LOG_ERROR("Failed to create directory: " << path);
    }
}

// =============================================================================
// HELPER: Verify PCAP file exists and has content
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
// HELPER: Tear down link between two nodes (for failure simulation)
// =============================================================================
// Guidance for [C] questions: This function simulates a link failure by
// setting the IPv4 interfaces to "down" state. This triggers routing
// protocol convergence behavior.
//
// For Distance Vector (RIP): Triggers route updates with increased metrics
// For Link State (GlobalRouting): Triggers SPF recalculation
// =============================================================================
void TearDownLink(Ptr<Node> nodeA, Ptr<Node> nodeB, uint32_t interfaceA, uint32_t interfaceB)
{
    NS_LOG_INFO("=== LINK FAILURE EVENT at t=" << Simulator::Now().GetSeconds() << "s ===");
    NS_LOG_INFO("Bringing down interfaces: Node " << nodeA->GetId() << " iface " << interfaceA
                << " and Node " << nodeB->GetId() << " iface " << interfaceB);

    nodeA->GetObject<Ipv4>()->SetDown(interfaceA);
    nodeB->GetObject<Ipv4>()->SetDown(interfaceB);
}

// =============================================================================
// HELPER: Write topology information to file
// =============================================================================
void WriteTopologyInfo(const std::string& outputPath, const std::string& info)
{
    std::ofstream file(outputPath + "topology-info.txt");
    file << info;
    file.close();
    std::cout << "Topology info written to: " << outputPath << "topology-info.txt" << std::endl;
}

// =============================================================================
// =============================================================================
// SCENARIO 1: LINK STATE vs DISTANCE VECTOR (LSDV)
// =============================================================================
// =============================================================================
//
// Guidance for [C]/[B] questions:
// This scenario demonstrates the difference between:
//   - Link State (LS): Uses Dijkstra's algorithm, global view of network
//   - Distance Vector (DV): Uses Bellman-Ford, distributed algorithm
//
// Key code sections for answering questions:
//   - RipHelper setup (lines with "RipHelper") - DV configuration
//   - Ipv4GlobalRoutingHelper (lines with "GlobalRouting") - LS configuration
//   - SetInterfaceMetric - link cost/metric assignment
//   - TearDownLink scheduling - link failure event
//
// Wireshark hints:
//   - Filter "rip" to see RIP update messages (DV mode)
//   - Filter "ip.ttl" to observe TTL decrement at each hop
//   - Compare routing table convergence times between LS and DV
// =============================================================================

void RunLsdvScenario(const std::string& outputPath, bool useLinkState)
{
    std::string modeStr = useLinkState ? "Link State (GlobalRouting)" : "Distance Vector (RIP)";
    NS_LOG_INFO("=== Running LSDV Scenario - " << modeStr << " ===");

    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "LSDV Scenario: " << modeStr << std::endl;
    std::cout << "========================================" << std::endl;

    // =========================================================================
    // Guidance for [C] questions: Node Creation
    // We create two endpoints and four routers.
    // The routed core has one low-cost path and one higher-cost backup path.
    // =========================================================================

    NS_LOG_INFO("Creating nodes...");
    Ptr<Node> src = CreateObject<Node>();
    Ptr<Node> r1 = CreateObject<Node>();
    Ptr<Node> r2 = CreateObject<Node>();
    Ptr<Node> r3 = CreateObject<Node>();
    Ptr<Node> r4 = CreateObject<Node>();
    Ptr<Node> dst = CreateObject<Node>();

    Names::Add("SRC", src);
    Names::Add("R1", r1);
    Names::Add("R2", r2);
    Names::Add("R3", r3);
    Names::Add("R4", r4);
    Names::Add("DST", dst);

    NodeContainer routers(r1, r2, r3, r4);
    NodeContainer endpoints(src, dst);
    NodeContainer allNodes(src, r1, r2, r3, r4, dst);

    // Node containers for each link
    NodeContainer linkSrcR1(src, r1);
    NodeContainer linkR1R2(r1, r2);
    NodeContainer linkR1R3(r1, r3);
    NodeContainer linkR2R3(r2, r3);
    NodeContainer linkR3R4(r3, r4);
    NodeContainer linkR2R4(r2, r4);
    NodeContainer linkR4Dst(r4, dst);

    // =========================================================================
    // Guidance for [C] questions: Channel/Link Creation
    // Using CSMA (Carrier Sense Multiple Access) channels similar to Ethernet
    // DataRate and Delay affect routing metrics and convergence time
    // =========================================================================

    NS_LOG_INFO("Creating channels...");
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", DataRateValue(DataRate("100Mbps")));
    csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));

    NetDeviceContainer devSrcR1 = csma.Install(linkSrcR1);
    NetDeviceContainer devR1R2 = csma.Install(linkR1R2);
    NetDeviceContainer devR1R3 = csma.Install(linkR1R3);
    NetDeviceContainer devR2R3 = csma.Install(linkR2R3);
    NetDeviceContainer devR3R4 = csma.Install(linkR3R4);
    NetDeviceContainer devR2R4 = csma.Install(linkR2R4);
    NetDeviceContainer devR4Dst = csma.Install(linkR4Dst);

    // =========================================================================
    // Guidance for [C]/[B] questions: Routing Protocol Selection
    //
    // LINK STATE MODE (useLinkState=true):
    //   - Uses Ipv4GlobalRoutingHelper which computes shortest paths using
    //     Dijkstra's algorithm based on global network view
    //   - Routes are computed at simulation start and recomputed on changes
    //   - Mimics OSPF-like behavior (centralized SPF computation)
    //
    // DISTANCE VECTOR MODE (useLinkState=false):
    //   - Uses RipHelper which implements RIP (Routing Information Protocol)
    //   - Routes are learned through periodic updates from neighbors
    //   - Uses Bellman-Ford algorithm with distributed computation
    //   - RIP updates visible in Wireshark as UDP port 520 packets
    // =========================================================================

    NS_LOG_INFO("Configuring routing protocol: " << modeStr);

    InternetStackHelper internet;
    internet.SetIpv6StackInstall(false);

    if (useLinkState)
    {
        // Link State mode: Use GlobalRouting (Dijkstra-based)
        // Guidance: RespondToInterfaceEvents enables route recomputation on failure
        Config::SetDefault("ns3::Ipv4GlobalRouting::RespondToInterfaceEvents",
                          BooleanValue(true));
        internet.Install(allNodes);
    }
    else
    {
        // Distance Vector mode: Use RIP
        RipHelper ripRouting;

        // =====================================================================
        // Guidance for [C] questions: RIP Interface Configuration
        // ExcludeInterface: Exclude interfaces from RIP (e.g., end hosts)
        // SetInterfaceMetric: Set link costs (affects path selection)
        // =====================================================================

        // =====================================================================
        // Guidance for [C]/[B] questions: Link Metric Configuration
        // The R3-R4 link has higher cost, so traffic initially prefers the
        // R1-R2-R4 path. When R2-R4 fails, routing converges to R1-R3-R4.
        // =====================================================================
        ripRouting.ExcludeInterface(r1, 1); // Keep the SRC access network static
        ripRouting.ExcludeInterface(r4, 3); // Keep the DST access network static
        ripRouting.SetInterfaceMetric(r3, 3, 10);
        ripRouting.SetInterfaceMetric(r4, 1, 10);

        Ipv4ListRoutingHelper listRH;
        listRH.Add(ripRouting, 0);

        internet.SetRoutingHelper(listRH);
        internet.Install(routers);

        // Install basic internet stack on endpoints (no RIP)
        InternetStackHelper internetEndpoints;
        internetEndpoints.SetIpv6StackInstall(false);
        internetEndpoints.Install(endpoints);
    }

    // =========================================================================
    // Guidance for [C]/[B] questions: IP Address Assignment
    // Each link is a separate subnet (10.1.x.0/24)
    // These addresses are visible in Wireshark IP headers
    // =========================================================================

    NS_LOG_INFO("Assigning IP addresses...");
    Ipv4AddressHelper ipv4;

    ipv4.SetBase("10.1.1.0", "255.255.255.0");  // SRC-R1 subnet
    Ipv4InterfaceContainer ifSrcR1 = ipv4.Assign(devSrcR1);

    ipv4.SetBase("10.1.2.0", "255.255.255.0");  // R1-R2 subnet
    Ipv4InterfaceContainer ifR1R2 = ipv4.Assign(devR1R2);

    ipv4.SetBase("10.1.3.0", "255.255.255.0");  // R1-R3 subnet
    Ipv4InterfaceContainer ifR1R3 = ipv4.Assign(devR1R3);

    ipv4.SetBase("10.1.4.0", "255.255.255.0");  // R2-R3 subnet
    Ipv4InterfaceContainer ifR2R3 = ipv4.Assign(devR2R3);

    ipv4.SetBase("10.1.5.0", "255.255.255.0");  // R3-R4 subnet (higher metric)
    Ipv4InterfaceContainer ifR3R4 = ipv4.Assign(devR3R4);

    ipv4.SetBase("10.1.6.0", "255.255.255.0");  // R2-R4 subnet
    Ipv4InterfaceContainer ifR2R4 = ipv4.Assign(devR2R4);

    ipv4.SetBase("10.1.7.0", "255.255.255.0");  // R4-DST subnet
    Ipv4InterfaceContainer ifR4Dst = ipv4.Assign(devR4Dst);

    ifR3R4.SetMetric(0, 10);
    ifR3R4.SetMetric(1, 10);

    // =========================================================================
    // Configure static routes for endpoints (in DV mode) or global routes
    // =========================================================================

    if (useLinkState)
    {
        Ipv4GlobalRoutingHelper::PopulateRoutingTables();
    }
    else
    {
        // Set default routes for source and destination
        Ptr<Ipv4StaticRouting> staticRouting;
        staticRouting = Ipv4RoutingHelper::GetRouting<Ipv4StaticRouting>(
            src->GetObject<Ipv4>()->GetRoutingProtocol());
        staticRouting->SetDefaultRoute("10.1.1.2", 1);  // Via R1

        staticRouting = Ipv4RoutingHelper::GetRouting<Ipv4StaticRouting>(
            dst->GetObject<Ipv4>()->GetRoutingProtocol());
        staticRouting->SetDefaultRoute("10.1.7.1", 1);  // Via R4
    }

    // =========================================================================
    // Guidance for [C]/[B] questions: Application Traffic Generation
    // Using Ping (ICMP Echo) to generate traffic and verify connectivity
    // Ping shows both path selection and TTL behavior
    // =========================================================================

    NS_LOG_INFO("Creating ping application...");
    PingHelper ping(ifR4Dst.GetAddress(1));  // Ping to DST's access-network address
    ping.SetAttribute("Interval", TimeValue(Seconds(1)));
    ping.SetAttribute("Size", UintegerValue(64));
    ping.SetAttribute("VerboseMode", EnumValue(Ping::VerboseMode::VERBOSE));

    ApplicationContainer pingApp = ping.Install(src);
    pingApp.Start(Seconds(5));
    pingApp.Stop(Seconds(90));

    // =========================================================================
    // Guidance for [C]/[B] questions: Link Failure Event
    // At t=40s, we bring down the preferred R2-R4 link
    // This triggers routing convergence:
    //   - LS mode: SPF recalculation, fast convergence
    //   - DV mode: RIP updates propagate, slower convergence
    // =========================================================================

    NS_LOG_INFO("Scheduling link failure at t=40s...");
    // R2's interface to R4 is interface 3, R4's interface to R2 is interface 2
    Simulator::Schedule(Seconds(40), &TearDownLink, r2, r4, 3, 2);

    // =========================================================================
    // Guidance for [W] questions: Routing Table Logging
    // Print routing tables at different times to observe convergence
    // =========================================================================

    Ptr<OutputStreamWrapper> routingStream =
        Create<OutputStreamWrapper>(outputPath + "routing-tables.txt", std::ios::out);

    Ipv4RoutingHelper::PrintRoutingTableAllAt(Seconds(10), routingStream);
    Ipv4RoutingHelper::PrintRoutingTableAllAt(Seconds(35), routingStream);
    Ipv4RoutingHelper::PrintRoutingTableAllAt(Seconds(45), routingStream);
    Ipv4RoutingHelper::PrintRoutingTableAllAt(Seconds(60), routingStream);
    Ipv4RoutingHelper::PrintRoutingTableAllAt(Seconds(80), routingStream);

    // =========================================================================
    // Guidance for [W] questions: PCAP Capture Points
    // Enable PCAP on all links to capture:
    //   - RIP update messages (DV mode) - UDP port 520
    //   - ICMP ping traffic
    //   - Routing changes after link failure
    //
    // Wireshark filters:
    //   - "rip" - Show RIP protocol messages
    //   - "icmp" - Show ICMP Echo Request/Reply
    //   - "ip.ttl" - Observe TTL changes at each hop
    // =========================================================================

    if (g_pcapEnabled)
    {
        csma.EnablePcap(outputPath + "lsdv-src-r1", devSrcR1.Get(0), true);
        csma.EnablePcap(outputPath + "lsdv-r1-r2", devR1R2.Get(0), true);
        csma.EnablePcap(outputPath + "lsdv-r1-r3", devR1R3.Get(0), true);
        csma.EnablePcap(outputPath + "lsdv-r2-r3", devR2R3.Get(0), true);
        csma.EnablePcap(outputPath + "lsdv-r3-r4", devR3R4.Get(0), true);
        csma.EnablePcap(outputPath + "lsdv-r2-r4", devR2R4.Get(0), true);
        csma.EnablePcap(outputPath + "lsdv-r4-dst", devR4Dst.Get(0), true);
    }

    // Write topology information
    std::stringstream topoInfo;
    topoInfo << "LSDV Scenario Topology - " << modeStr << "\n";
    topoInfo << "=========================================\n\n";
    topoInfo << "Nodes:\n";
    topoInfo << "  SRC: 10.1.1.1 (to R1)\n";
    topoInfo << "  R1:  10.1.1.2 (to SRC), 10.1.2.1 (to R2), 10.1.3.1 (to R3)\n";
    topoInfo << "  R2:  10.1.2.2 (to R1), 10.1.4.1 (to R3), 10.1.6.1 (to R4)\n";
    topoInfo << "  R3:  10.1.3.2 (to R1), 10.1.4.2 (to R2), 10.1.5.1 (to R4)\n";
    topoInfo << "  R4:  10.1.5.2 (to R3), 10.1.6.2 (to R2), 10.1.7.1 (to DST)\n";
    topoInfo << "  DST: 10.1.7.2 (to R4)\n\n";
    topoInfo << "Links:\n";
    topoInfo << "  SRC-R1: 10.1.1.0/24 (metric 1)\n";
    topoInfo << "  R1-R2:  10.1.2.0/24 (metric 1)\n";
    topoInfo << "  R1-R3:  10.1.3.0/24 (metric 1)\n";
    topoInfo << "  R2-R3:  10.1.4.0/24 (metric 1)\n";
    topoInfo << "  R3-R4:  10.1.5.0/24 (metric 10, backup path)\n";
    topoInfo << "  R2-R4:  10.1.6.0/24 (metric 1, FAILS at t=40s)\n";
    topoInfo << "  R4-DST: 10.1.7.0/24 (metric 1)\n\n";
    topoInfo << "Events:\n";
    topoInfo << "  t=5s:  Ping starts (SRC -> 10.1.7.2)\n";
    topoInfo << "  t=40s: R2-R4 link fails\n";
    topoInfo << "  t=90s: Simulation ends\n";
    WriteTopologyInfo(outputPath, topoInfo.str());

    Simulator::Stop(Seconds(95));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("LSDV scenario complete.");
}

// =============================================================================
// =============================================================================
// SCENARIO 2: OSPF-LIKE LINK STATE ADVERTISEMENTS
// =============================================================================
// =============================================================================
//
// IMPORTANT NOTE: This is an instructional OSPF-like approximation, NOT a full
// OSPF implementation. ns-3's basic internet module does not include OSPF.
//
// This scenario demonstrates OSPF concepts:
//   - Periodic Link State Advertisements (LSAs) flooded between routers
//   - LSAs contain link information (neighbors, costs)
//   - Flooding ensures all routers have consistent network view
//
// Guidance for [C]/[B] questions:
//   - LsaApplication class sends periodic LSA packets
//   - LSAs are sent via UDP to port 50001 (avoiding DISCARD port)
//   - Each router floods LSAs to all neighbors
//
// Wireshark hints:
//   - Filter "udp.port==50001" to see LSA packets
//   - LSA payload contains router ID and link information
//   - Observe periodic LSA flooding interval
// =============================================================================

// =============================================================================
// Custom LSA Application for OSPF-like behavior
// =============================================================================
// Guidance for [C] questions: This application simulates OSPF LSA flooding.
// Each router periodically sends LSA messages to all neighbors.
// LSA contains: Router ID, Sequence Number, Link Information
// =============================================================================

class LsaApplication : public Application
{
public:
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::LsaApplication")
            .SetParent<Application>()
            .SetGroupName("Applications")
            .AddConstructor<LsaApplication>();
        return tid;
    }

    LsaApplication() : m_socket(nullptr), m_running(false), m_sequenceNumber(0) {}
    virtual ~LsaApplication() { m_socket = nullptr; }

    void Setup(std::vector<Ipv4Address> neighbors, uint32_t routerId, Time interval)
    {
        m_neighbors = neighbors;
        m_routerId = routerId;
        m_interval = interval;
    }

private:
    virtual void StartApplication() override
    {
        m_running = true;
        m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        m_socket->Bind();
        SendLsa();
    }

    virtual void StopApplication() override
    {
        m_running = false;
        if (m_socket)
        {
            m_socket->Close();
        }
    }

    void SendLsa()
    {
        if (!m_running) return;

        // =====================================================================
        // Guidance for [C]/[B] questions: LSA Packet Format
        // The LSA packet contains:
        //   - Router ID (4 bytes)
        //   - Sequence Number (4 bytes)
        //   - Number of neighbors (4 bytes)
        //   - Neighbor addresses (4 bytes each)
        //
        // This mimics OSPF LSA structure (simplified for educational purposes)
        // =====================================================================

        // Create LSA payload
        std::stringstream lsaData;
        lsaData << "LSA|RouterID=" << m_routerId
                << "|Seq=" << m_sequenceNumber
                << "|Neighbors=" << m_neighbors.size();
        for (const auto& neighbor : m_neighbors)
        {
            lsaData << "|" << neighbor;
        }

        std::string lsaStr = lsaData.str();
        Ptr<Packet> packet = Create<Packet>((uint8_t*)lsaStr.c_str(), lsaStr.length());

        // Flood LSA to all neighbors
        for (const auto& neighbor : m_neighbors)
        {
            m_socket->SendTo(packet, 0, InetSocketAddress(neighbor, LSA_PORT));
        }

        m_sequenceNumber++;

        NS_LOG_INFO("Router " << m_routerId << " sent LSA seq=" << (m_sequenceNumber-1)
                    << " to " << m_neighbors.size() << " neighbors");

        // Schedule next LSA
        Simulator::Schedule(m_interval, &LsaApplication::SendLsa, this);
    }

    Ptr<Socket> m_socket;
    std::vector<Ipv4Address> m_neighbors;
    uint32_t m_routerId;
    Time m_interval;
    bool m_running;
    uint32_t m_sequenceNumber;
};

void RunOspfLikeScenario(const std::string& outputPath)
{
    NS_LOG_INFO("=== Running OSPF-Like Scenario ===");

    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "OSPF-Like LSA Flooding Scenario" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "NOTE: This is an instructional approximation of OSPF." << std::endl;
    std::cout << "LSA packets are sent on UDP port " << LSA_PORT << std::endl;
    std::cout << std::endl;

    // =========================================================================
    // Guidance for [C] questions: Topology for OSPF-like scenario
    // Triangle topology: R1 -- R2 -- R3 -- R1
    // Each router has 2 neighbors and floods LSAs to both
    // =========================================================================

    NS_LOG_INFO("Creating router nodes...");
    NodeContainer routers;
    routers.Create(3);

    Names::Add("R1", routers.Get(0));
    Names::Add("R2", routers.Get(1));
    Names::Add("R3", routers.Get(2));

    // Create links
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("2ms"));

    // =========================================================================
    // Guidance for [C] questions: Link Metric Configuration
    // In OSPF, interface costs affect shortest path calculation
    // Here we set costs via metric attribute (for documentation)
    // =========================================================================

    NetDeviceContainer devR1R2 = p2p.Install(routers.Get(0), routers.Get(1));
    NetDeviceContainer devR2R3 = p2p.Install(routers.Get(1), routers.Get(2));
    NetDeviceContainer devR3R1 = p2p.Install(routers.Get(2), routers.Get(0));

    // Install Internet stack with global routing
    InternetStackHelper internet;
    internet.Install(routers);

    // =========================================================================
    // Guidance for [C]/[B] questions: IP Address Assignment for OSPF
    // Addresses are used for LSA destination and router identification
    // =========================================================================

    Ipv4AddressHelper ipv4;

    ipv4.SetBase("10.0.1.0", "255.255.255.0");  // R1-R2 link
    Ipv4InterfaceContainer ifR1R2 = ipv4.Assign(devR1R2);

    ipv4.SetBase("10.0.2.0", "255.255.255.0");  // R2-R3 link
    Ipv4InterfaceContainer ifR2R3 = ipv4.Assign(devR2R3);

    ipv4.SetBase("10.0.3.0", "255.255.255.0");  // R3-R1 link
    Ipv4InterfaceContainer ifR3R1 = ipv4.Assign(devR3R1);

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // =========================================================================
    // Guidance for [C]/[B] questions: LSA Application Setup
    // Each router runs LsaApplication that:
    //   1. Sends periodic LSAs every 10 seconds
    //   2. Floods LSAs to all direct neighbors
    //   3. Includes router ID and neighbor list in LSA
    //
    // This mimics OSPF Hello/LSA behavior (simplified)
    // =========================================================================

    NS_LOG_INFO("Setting up LSA applications...");

    // R1's neighbors: R2 (10.0.1.2) and R3 (10.0.3.1)
    Ptr<LsaApplication> lsaR1 = CreateObject<LsaApplication>();
    std::vector<Ipv4Address> neighborsR1 = {ifR1R2.GetAddress(1), ifR3R1.GetAddress(0)};
    lsaR1->Setup(neighborsR1, 1, Seconds(10));
    routers.Get(0)->AddApplication(lsaR1);
    lsaR1->SetStartTime(Seconds(1));
    lsaR1->SetStopTime(Seconds(60));

    // R2's neighbors: R1 (10.0.1.1) and R3 (10.0.2.2)
    Ptr<LsaApplication> lsaR2 = CreateObject<LsaApplication>();
    std::vector<Ipv4Address> neighborsR2 = {ifR1R2.GetAddress(0), ifR2R3.GetAddress(1)};
    lsaR2->Setup(neighborsR2, 2, Seconds(10));
    routers.Get(1)->AddApplication(lsaR2);
    lsaR2->SetStartTime(Seconds(2));  // Slight offset to avoid collision
    lsaR2->SetStopTime(Seconds(60));

    // R3's neighbors: R2 (10.0.2.1) and R1 (10.0.3.2)
    Ptr<LsaApplication> lsaR3 = CreateObject<LsaApplication>();
    std::vector<Ipv4Address> neighborsR3 = {ifR2R3.GetAddress(0), ifR3R1.GetAddress(1)};
    lsaR3->Setup(neighborsR3, 3, Seconds(10));
    routers.Get(2)->AddApplication(lsaR3);
    lsaR3->SetStartTime(Seconds(3));  // Slight offset
    lsaR3->SetStopTime(Seconds(60));

    // =========================================================================
    // Guidance for [W] questions: PCAP Capture for LSA Analysis
    //
    // Wireshark analysis:
    //   - Filter: "udp.port==50001" to see only LSA packets
    //   - Observe periodic flooding (every 10 seconds)
    //   - Each router sends to 2 neighbors
    //   - LSA payload visible in packet data
    // =========================================================================

    if (g_pcapEnabled)
    {
        p2p.EnablePcap(outputPath + "ospf-like-r1r2", devR1R2.Get(0), true);
        p2p.EnablePcap(outputPath + "ospf-like-r2r3", devR2R3.Get(0), true);
        p2p.EnablePcap(outputPath + "ospf-like-r3r1", devR3R1.Get(0), true);
    }

    // Write topology information
    std::stringstream topoInfo;
    topoInfo << "OSPF-Like Scenario Topology\n";
    topoInfo << "=========================================\n\n";
    topoInfo << "NOTE: This is an instructional OSPF approximation.\n";
    topoInfo << "LSA port: " << LSA_PORT << " (to avoid DISCARD)\n\n";
    topoInfo << "Triangle Topology:\n";
    topoInfo << "        R1\n";
    topoInfo << "       /  \\\n";
    topoInfo << "      /    \\\n";
    topoInfo << "     R3----R2\n\n";
    topoInfo << "IP Addresses:\n";
    topoInfo << "  R1-R2 link: 10.0.1.0/24 (R1=.1, R2=.2)\n";
    topoInfo << "  R2-R3 link: 10.0.2.0/24 (R2=.1, R3=.2)\n";
    topoInfo << "  R3-R1 link: 10.0.3.0/24 (R3=.1, R1=.2)\n\n";
    topoInfo << "LSA Flooding:\n";
    topoInfo << "  Interval: 10 seconds\n";
    topoInfo << "  Each router floods to 2 neighbors\n\n";
    topoInfo << "Wireshark filter: udp.port==" << LSA_PORT << "\n";
    WriteTopologyInfo(outputPath, topoInfo.str());

    Simulator::Stop(Seconds(65));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("OSPF-Like scenario complete.");
}

// =============================================================================
// =============================================================================
// SCENARIO 3: TTL AND ICMP TIME EXCEEDED
// =============================================================================
// =============================================================================
//
// Guidance for [C]/[B] questions:
// This scenario demonstrates TTL field behavior:
//   - Each router decrements TTL by 1
//   - When TTL reaches 0, router drops packet and sends ICMP Time Exceeded
//   - ICMP Time Exceeded is Type 11, Code 0
//
// Key code sections:
//   - Socket::SetIpTtl() - sets initial TTL value
//   - ICMP Type 11 generation is automatic by ns-3 IP stack
//
// Wireshark hints:
//   - Filter "icmp.type==11" for Time Exceeded messages
//   - Filter "icmp" for all ICMP traffic
//   - Check Protocol field = 1 (ICMP) in IPv4 header
//   - ICMP Time Exceeded includes copy of original IP header
// =============================================================================

void RunTtlIcmpScenario(const std::string& outputPath)
{
    NS_LOG_INFO("=== Running TTL-ICMP Scenario ===");

    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "TTL Expiry and ICMP Time Exceeded" << std::endl;
    std::cout << "========================================" << std::endl;

    // =========================================================================
    // Guidance for [C] questions: Linear Topology
    // SRC -- R1 -- R2 -- R3 -- DST (4 hops)
    // Packets with TTL=1 expire at R1
    // Packets with TTL=2 expire at R2
    // Packets with TTL=3 expire at R3
    // Packets with TTL=4 reach DST
    // =========================================================================

    NS_LOG_INFO("Creating nodes for TTL-ICMP scenario...");
    NodeContainer allNodes;
    allNodes.Create(5);

    Ptr<Node> src = allNodes.Get(0);
    Ptr<Node> r1 = allNodes.Get(1);
    Ptr<Node> r2 = allNodes.Get(2);
    Ptr<Node> r3 = allNodes.Get(3);
    Ptr<Node> dst = allNodes.Get(4);

    Names::Add("SRC-TTL", src);
    Names::Add("R1-TTL", r1);
    Names::Add("R2-TTL", r2);
    Names::Add("R3-TTL", r3);
    Names::Add("DST-TTL", dst);

    // Create point-to-point links
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("2ms"));

    NetDeviceContainer devSrcR1 = p2p.Install(src, r1);
    NetDeviceContainer devR1R2 = p2p.Install(r1, r2);
    NetDeviceContainer devR2R3 = p2p.Install(r2, r3);
    NetDeviceContainer devR3Dst = p2p.Install(r3, dst);

    // Install Internet stack
    InternetStackHelper internet;
    internet.Install(allNodes);

    // =========================================================================
    // Guidance for [C]/[B] questions: IP Address Assignment
    // Each hop is a separate subnet
    // These addresses appear in ICMP Time Exceeded source field
    // =========================================================================

    Ipv4AddressHelper ipv4;

    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer ifSrcR1 = ipv4.Assign(devSrcR1);

    ipv4.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer ifR1R2 = ipv4.Assign(devR1R2);

    ipv4.SetBase("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer ifR2R3 = ipv4.Assign(devR2R3);

    ipv4.SetBase("10.1.4.0", "255.255.255.0");
    Ipv4InterfaceContainer ifR3Dst = ipv4.Assign(devR3Dst);

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // =========================================================================
    // Guidance for [C]/[B] questions: TTL Configuration
    // We create UDP sockets and explicitly set TTL using SetIpTtl()
    //
    // TTL=1: Expires at R1 (first router)
    // TTL=2: Expires at R2 (second router)
    // TTL=3: Expires at R3 (third router)
    // TTL=4: Reaches DST
    //
    // When TTL expires, router sends ICMP Time Exceeded (Type 11, Code 0)
    // The ICMP message includes the original IP header + first 8 bytes
    // =========================================================================

    uint16_t destPort = DATA_PORT;  // Using safe port (not DISCARD)
    Ipv4Address destAddr = ifR3Dst.GetAddress(1);  // DST address

    // Create UDP server at destination
    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory",
                                 InetSocketAddress(Ipv4Address::GetAny(), destPort));
    ApplicationContainer serverApp = sinkHelper.Install(dst);
    serverApp.Start(Seconds(0));
    serverApp.Stop(Seconds(30));

    // =========================================================================
    // Guidance for [C] questions: Creating Low-TTL Packets
    // Each socket is configured with a different TTL value
    // Simulator::Schedule() sends packets at specific times
    // =========================================================================

    // Send packet with TTL=1 (expires at R1)
    Ptr<Socket> socket1 = Socket::CreateSocket(src, UdpSocketFactory::GetTypeId());
    socket1->SetIpTtl(1);
    Simulator::Schedule(Seconds(1), [socket1, destAddr, destPort]() {
        socket1->Connect(InetSocketAddress(destAddr, destPort));
        Ptr<Packet> packet = Create<Packet>(64);
        socket1->Send(packet);
        NS_LOG_INFO("Sent packet with TTL=1 (should expire at R1, generate ICMP from 10.1.1.2)");
    });

    // Send packet with TTL=2 (expires at R2)
    Ptr<Socket> socket2 = Socket::CreateSocket(src, UdpSocketFactory::GetTypeId());
    socket2->SetIpTtl(2);
    Simulator::Schedule(Seconds(3), [socket2, destAddr, destPort]() {
        socket2->Connect(InetSocketAddress(destAddr, destPort));
        Ptr<Packet> packet = Create<Packet>(64);
        socket2->Send(packet);
        NS_LOG_INFO("Sent packet with TTL=2 (should expire at R2, generate ICMP from 10.1.2.2)");
    });

    // Send packet with TTL=3 (expires at R3)
    Ptr<Socket> socket3 = Socket::CreateSocket(src, UdpSocketFactory::GetTypeId());
    socket3->SetIpTtl(3);
    Simulator::Schedule(Seconds(5), [socket3, destAddr, destPort]() {
        socket3->Connect(InetSocketAddress(destAddr, destPort));
        Ptr<Packet> packet = Create<Packet>(64);
        socket3->Send(packet);
        NS_LOG_INFO("Sent packet with TTL=3 (should expire at R3, generate ICMP from 10.1.3.2)");
    });

    // Send packet with TTL=4 (reaches destination)
    Ptr<Socket> socket4 = Socket::CreateSocket(src, UdpSocketFactory::GetTypeId());
    socket4->SetIpTtl(4);
    Simulator::Schedule(Seconds(7), [socket4, destAddr, destPort]() {
        socket4->Connect(InetSocketAddress(destAddr, destPort));
        Ptr<Packet> packet = Create<Packet>(64);
        socket4->Send(packet);
        NS_LOG_INFO("Sent packet with TTL=4 (should reach DST)");
    });

    // Send packet with TTL=64 (normal, reaches destination)
    Ptr<Socket> socket5 = Socket::CreateSocket(src, UdpSocketFactory::GetTypeId());
    socket5->SetIpTtl(64);
    Simulator::Schedule(Seconds(9), [socket5, destAddr, destPort]() {
        socket5->Connect(InetSocketAddress(destAddr, destPort));
        Ptr<Packet> packet = Create<Packet>(64);
        socket5->Send(packet);
        NS_LOG_INFO("Sent packet with TTL=64 (normal TTL, should reach DST)");
    });

    // =========================================================================
    // Guidance for [W] questions: PCAP Capture Points
    //
    // Wireshark analysis for TTL-ICMP:
    //   - Filter "icmp.type==11" to see only Time Exceeded messages
    //   - Filter "icmp.type==11 && icmp.code==0" for TTL exceeded in transit
    //   - Check the source IP of ICMP reply = router that dropped packet
    //   - ICMP payload contains original IP header (check original TTL=0)
    //   - Protocol field in IPv4 header = 1 (ICMP)
    // =========================================================================

    if (g_pcapEnabled)
    {
        // Capture at source to see outgoing packets and incoming ICMP errors
        p2p.EnablePcap(outputPath + "ttl-icmp-src", devSrcR1.Get(0), true);
        // Capture at each router
        p2p.EnablePcap(outputPath + "ttl-icmp-r1", devSrcR1.Get(1), true);
        p2p.EnablePcap(outputPath + "ttl-icmp-r2", devR1R2.Get(1), true);
        p2p.EnablePcap(outputPath + "ttl-icmp-r3", devR2R3.Get(1), true);
        // Capture at destination
        p2p.EnablePcap(outputPath + "ttl-icmp-dst", devR3Dst.Get(1), true);
    }

    // Write topology information
    std::stringstream topoInfo;
    topoInfo << "TTL-ICMP Scenario Topology\n";
    topoInfo << "=========================================\n\n";
    topoInfo << "Linear Topology (4 hops):\n";
    topoInfo << "  [SRC]----[R1]----[R2]----[R3]----[DST]\n";
    topoInfo << "  10.1.1.1  .2|.1   .2|.1   .2|.1   .2\n\n";
    topoInfo << "IP Addresses:\n";
    topoInfo << "  SRC: 10.1.1.1\n";
    topoInfo << "  R1:  10.1.1.2 (to SRC), 10.1.2.1 (to R2)\n";
    topoInfo << "  R2:  10.1.2.2 (to R1), 10.1.3.1 (to R3)\n";
    topoInfo << "  R3:  10.1.3.2 (to R2), 10.1.4.1 (to DST)\n";
    topoInfo << "  DST: 10.1.4.2\n\n";
    topoInfo << "TTL Test Packets:\n";
    topoInfo << "  t=1s: TTL=1, expires at R1 (ICMP from 10.1.1.2)\n";
    topoInfo << "  t=3s: TTL=2, expires at R2 (ICMP from 10.1.2.2)\n";
    topoInfo << "  t=5s: TTL=3, expires at R3 (ICMP from 10.1.3.2)\n";
    topoInfo << "  t=7s: TTL=4, reaches DST\n";
    topoInfo << "  t=9s: TTL=64, reaches DST (normal)\n\n";
    topoInfo << "Wireshark filters:\n";
    topoInfo << "  icmp.type==11         - Time Exceeded messages\n";
    topoInfo << "  icmp.type==11 && icmp.code==0 - TTL exceeded in transit\n";
    topoInfo << "  icmp                  - All ICMP traffic\n\n";
    topoInfo << "ICMP Time Exceeded source IPs identify routers on path.\n";
    WriteTopologyInfo(outputPath, topoInfo.str());

    Simulator::Stop(Seconds(15));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("TTL-ICMP scenario complete.");
}

// =============================================================================
// MAIN FUNCTION
// =============================================================================

int main(int argc, char* argv[])
{
    std::string scenario = "lsdv";
    std::string mode = "ls";  // For lsdv: "ls" or "dv"
    int pcap = 0;
    bool verbose = false;

    // =========================================================================
    // Guidance for [C] questions: Command-line Argument Parsing
    // --scenario: selects which scenario to run (lsdv, ospf-like, ttl-icmp)
    // --pcap: enables PCAP capture (required for Wireshark analysis)
    // --mode: for lsdv scenario, selects Link State (ls) or Distance Vector (dv)
    // =========================================================================

    CommandLine cmd(__FILE__);
    cmd.AddValue("scenario", "Scenario: lsdv, ospf-like, ttl-icmp", scenario);
    cmd.AddValue("mode", "For lsdv scenario: ls (Link State) or dv (Distance Vector)", mode);
    cmd.AddValue("pcap", "Enable PCAP capture (0 or 1)", pcap);
    cmd.AddValue("verbose", "Enable verbose logging", verbose);
    cmd.Parse(argc, argv);

    g_pcapEnabled = (pcap == 1);

    if (verbose)
    {
        LogComponentEnable("RoutingLab", LOG_LEVEL_INFO);
        LogComponentEnable("Rip", LOG_LEVEL_INFO);
        LogComponentEnable("Ping", LOG_LEVEL_INFO);
    }

    // Validate scenario
    if (scenario != "lsdv" && scenario != "ospf-like" && scenario != "ttl-icmp")
    {
        std::cerr << "Invalid scenario: " << scenario << std::endl;
        std::cerr << "Valid scenarios: lsdv, ospf-like, ttl-icmp" << std::endl;
        return 1;
    }

    // Validate mode for lsdv
    if (scenario == "lsdv" && mode != "ls" && mode != "dv")
    {
        std::cerr << "Invalid mode for lsdv: " << mode << std::endl;
        std::cerr << "Valid modes: ls (Link State), dv (Distance Vector)" << std::endl;
        return 1;
    }

    std::cout << "=== ns-3 Routing Lab (Lab 4) ===" << std::endl;
    std::cout << "Scenario: " << scenario << std::endl;
    if (scenario == "lsdv")
    {
        std::cout << "Mode: " << (mode == "ls" ? "Link State" : "Distance Vector") << std::endl;
    }
    std::cout << "PCAP enabled: " << (g_pcapEnabled ? "yes" : "no") << std::endl;

    if (!g_pcapEnabled)
    {
        std::cout << "Note: Use --pcap=1 to enable PCAP capture for Wireshark analysis" << std::endl;
    }

    // Create main output directory
    EnsureDirectory(g_outputDir);

    bool success = true;

    // =========================================================================
    // Run selected scenario
    // =========================================================================

    if (scenario == "lsdv")
    {
        std::string outputPath = g_outputDir + "lsdv/";
        EnsureDirectory(outputPath);

        bool useLinkState = (mode == "ls");
        RunLsdvScenario(outputPath, useLinkState);

        if (g_pcapEnabled)
        {
            // PCAP files use node names: prefix-NodeName-DeviceIndex.pcap
            success = success && VerifyPcapFile(outputPath + "lsdv-src-r1-SRC-0.pcap");
        }
    }
    else if (scenario == "ospf-like")
    {
        std::string outputPath = g_outputDir + "ospf-like/";
        EnsureDirectory(outputPath);

        RunOspfLikeScenario(outputPath);

        if (g_pcapEnabled)
        {
            // PCAP files use node names: prefix-NodeName-DeviceIndex.pcap
            success = success && VerifyPcapFile(outputPath + "ospf-like-r1r2-R1-0.pcap");
        }
    }
    else if (scenario == "ttl-icmp")
    {
        std::string outputPath = g_outputDir + "ttl-icmp/";
        EnsureDirectory(outputPath);

        RunTtlIcmpScenario(outputPath);

        if (g_pcapEnabled)
        {
            // PCAP files use node names: prefix-NodeName-DeviceIndex.pcap
            success = success && VerifyPcapFile(outputPath + "ttl-icmp-src-SRC-TTL-0.pcap");
        }
    }

    std::cout << std::endl;
    std::cout << "=== Simulation Complete ===" << std::endl;
    std::cout << "Output directory: " << g_outputDir << std::endl;

    std::cout << std::endl;
    std::cout << "=== Wireshark Analysis Hints ===" << std::endl;
    if (scenario == "lsdv")
    {
        std::cout << "- Filter 'rip' to see RIP update messages (DV mode)" << std::endl;
        std::cout << "- Filter 'icmp' to see ping traffic" << std::endl;
        std::cout << "- Check routing-tables.txt for convergence analysis" << std::endl;
    }
    else if (scenario == "ospf-like")
    {
        std::cout << "- Filter 'udp.port==" << LSA_PORT << "' to see LSA packets" << std::endl;
        std::cout << "- Observe periodic LSA flooding (every 10 seconds)" << std::endl;
        std::cout << "- LSA payload contains Router ID and neighbors" << std::endl;
    }
    else if (scenario == "ttl-icmp")
    {
        std::cout << "- Filter 'icmp.type==11' for Time Exceeded messages" << std::endl;
        std::cout << "- Source IP of ICMP reply identifies the router" << std::endl;
        std::cout << "- Protocol field = 1 indicates ICMP" << std::endl;
    }

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
