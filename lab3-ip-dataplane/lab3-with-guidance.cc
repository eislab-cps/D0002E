/*
 * =============================================================================
 * ns-3 Wireshark Lab Simulation - IP
 * Extended version with seed-based randomization, NetAnim support,
 * and parameterized experiments.
 * =============================================================================
 *
 * Changes vs lab3-with-guidance.cc:
 *   - --seed <1..100>   Reproducible runs; same seed = identical output
 *   - PCAP always ON by default (--pcap=0 to disable); no more --pcap=1 needed
 *   - NetAnim XML produced per scenario with full packet metadata
 *   - MobilityHelper sets node positions per topology so NetAnim is readable
 *   - PacketMetadata::Enable() called once so every arrow carries header info
 *   - Output placed under seed<N>/ subfolder to keep runs separate
 *   - jitter (0..0.095 s, derived from seed) shifts packet send times
 *
 * =============================================================================
 * HOW TO RUN EACH SCENARIO
 * =============================================================================
 *
 * Build:
 *   ./ns3 build scratch/d0002e/lab3-with-guidance
 *
 * Run scenarios (outputs go to "scratch/d0002e/lab 3 output/seed<N>/"):
 *
 * 1) BASIC IPv4 FORWARDING:
 *    ./ns3 run "scratch/d0002e/lab3-with-guidance --scenario=basic-forwarding"
 *    ./ns3 run "scratch/d0002e/lab3-with-guidance --scenario=basic-forwarding --seed=42"
 *
 * 2) IPv4 FRAGMENTATION:
 *    ./ns3 run "scratch/d0002e/lab3-with-guidance --scenario=fragmentation"
 *    ./ns3 run "scratch/d0002e/lab3-with-guidance --scenario=fragmentation --packetSize=600"
 *    ./ns3 run "scratch/d0002e/lab3-with-guidance --scenario=fragmentation --packetSize=3500 --mtu=576"
 *
 * 3) ROUTING AND FORWARDING:
 *    ./ns3 run "scratch/d0002e/lab3-with-guidance --scenario=routing"
 *
 * 4) TTL EXPIRY (TRACEROUTE-STYLE):
 *    ./ns3 run "scratch/d0002e/lab3-with-guidance --scenario=ttl-expiry"
 *
 * 5) ALL SCENARIOS:
 *    ./ns3 run "scratch/d0002e/lab3-with-guidance --scenario=all"
 *    ./ns3 run "scratch/d0002e/lab3-with-guidance --scenario=all --seed=42 --verbose=true"
 *
 * Additional options:
 *   --pcap=0            Disable PCAP capture (default: enabled)
 *   --verbose=true      Enable detailed logging
 *   --packetSize=3500   UDP datagram size for fragmentation (default: 3500)
 *   --mtu=1500          MTU for source link in fragmentation scenario (default: 1500)
 *   --seed=100          RNG seed 1-100 (default: 100)
 *
 * =============================================================================
 * NETWORK TOPOLOGY
 * =============================================================================
 *
 * Basic Forwarding / TTL Expiry (5-node chain):
 *
 *   Source(n0)---Router1(n1)---Router2(n2)---Router3(n3)---Dest(n4)
 *   10.1.1.1    10.1.1.2      10.1.2.2      10.1.3.2      10.1.4.2
 *               10.1.2.1      10.1.3.1      10.1.4.1
 *
 * Fragmentation (3-node linear):
 *
 *   Source(n0) ---[MTU=g_mtu]--- Router(n1) ---[MTU=576]--- Dest(n2)
 *   10.1.1.1                    10.1.1.2                   10.1.2.2
 *                               10.1.2.1
 *
 * Routing (4-node diamond):
 *
 *                    Router1(n1)
 *   Source(n0) ---+               +--- Dest(n3)
 *                    Router2(n2)
 *
 * =============================================================================
 * QUESTIONS REFERENCE
 * =============================================================================
 *
 * [V] = Wireshark analysis verified by textbook
 * [W] = Wireshark analysis
 * [C] = Simulation code with explanation
 * [B] = Both Wireshark and simulation code
 * [T] = Textbook description only
 *
 * =============================================================================
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-apps-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"     // [NEW] ConstantPositionMobilityModel
#include "ns3/netanim-module.h"      // [NEW] AnimationInterface
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
// Packets larger than the bottleneck MTU will be fragmented by the IP layer
// =============================================================================
static uint32_t g_packetSize = 3500;

// =============================================================================
// Relevant to [C]: g_mtu configures the source-side link MTU
// The router-to-dest link is always 576 to force fragmentation
// =============================================================================
static uint32_t g_mtu = 1500;

// =============================================================================
// [NEW] g_pcapEnabled defaults to TRUE so PCAP is always produced.
// Pass --pcap=0 to disable. No more --pcap=1 needed.
// =============================================================================
static bool g_pcapEnabled = true;

// =============================================================================
// [NEW] Seed parameter for reproducible randomization (range 1-100, default 100)
// =============================================================================
static uint32_t g_seed = 100;

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
// [NEW] SetupMobility: install ConstantPositionMobilityModel on every node
// in the container using the supplied (x,y) position list.
// AnimationInterface reads positions from the mobility model; without this
// all nodes appear stacked at (0,0) in NetAnim.
// =============================================================================
static void SetupMobility(NodeContainer& nodes,
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
// [NEW] SetupNetAnim: common NetAnim configuration called inside each scenario
// after the AnimationInterface object has been constructed.
//
// Enables packet metadata (requires PacketMetadata::Enable() in main),
// sets per-node IPv4 counters, labels, colours, and sizes.
//
// nodeLabels must match the order of nodes in the container.
// nodeColors: vector of (R,G,B) triples in 0-255.
// =============================================================================
static void SetupNetAnim(AnimationInterface& anim,
                          NodeContainer& nodes,
                          const std::vector<std::string>& nodeLabels,
                          const std::vector<std::tuple<uint8_t,uint8_t,uint8_t>>& nodeColors,
                          double simStopTime)
{
    // -------------------------------------------------------------------------
    // [NEW] EnablePacketMetadata writes a meta-info attribute on every <p>
    // element: PPP header, IPv4 header (src/dst, TTL, protocol, frag fields),
    // ICMP or UDP header, payload size. Makes every arrow in NetAnim informative.
    // Requires PacketMetadata::Enable() called before topology setup (done in main).
    // -------------------------------------------------------------------------
    anim.EnablePacketMetadata(true);

    // [NEW] Live IPv4 packet counter overlay per node, polled every 0.5 s
    anim.EnableIpv4L3ProtocolCounters(Seconds(0), Seconds(simStopTime), Seconds(0.5));

    for (uint32_t i = 0; i < nodes.GetN() && i < nodeLabels.size(); ++i)
    {
        anim.UpdateNodeDescription(nodes.Get(i), nodeLabels[i]);
        if (i < nodeColors.size())
        {
            auto [r, g, b] = nodeColors[i];
            anim.UpdateNodeColor(nodes.Get(i), r, g, b);
        }
        anim.UpdateNodeSize(nodes.Get(i)->GetId(), 2.5, 2.5);
    }
}

// =============================================================================
// BASIC IPv4 FORWARDING SCENARIO
// =============================================================================
// Relevant to [V]: TTL decrements by 1 at each router hop (Section 4.3.1)
//
// Relevant to [W]: Capture at each router interface shows:
//   - Same source/destination IP throughout
//   - TTL decreasing by 1 per hop
//   - Different MAC addresses at each link
//
// Relevant to [B]: Source IP=10.1.1.1, Dest IP=10.1.4.2 visible in Wireshark.
//   TTL at source=64, at dest arrives with TTL=61 (decremented 3 times).
//
// Relevant to [C]: Ipv4GlobalRoutingHelper::PopulateRoutingTables() creates
// routing entries automatically based on network topology.
// =============================================================================

void RunBasicForwardingScenario(const std::string& outputPath,
                                 const std::string& animFile,
                                 double jitter)
{
    NS_LOG_INFO("=== Running Basic IPv4 Forwarding Scenario ===");
    NS_LOG_INFO("This scenario demonstrates IP datagram forwarding through routers.");
    NS_LOG_INFO("Open PCAPs in Wireshark to observe TTL decrement at each hop.");

    // =============================================================================
    // Relevant to [C]: 5-node chain: Source - R1 - R2 - R3 - Dest
    // =============================================================================
    NodeContainer allNodes;
    allNodes.Create(5);

    Ptr<Node> source  = allNodes.Get(0);
    Ptr<Node> router1 = allNodes.Get(1);
    Ptr<Node> router2 = allNodes.Get(2);
    Ptr<Node> router3 = allNodes.Get(3);
    Ptr<Node> dest    = allNodes.Get(4);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("2ms"));

    NetDeviceContainer devicesSourceR1 = p2p.Install(source,  router1);
    NetDeviceContainer devicesR1R2     = p2p.Install(router1, router2);
    NetDeviceContainer devicesR2R3     = p2p.Install(router2, router3);
    NetDeviceContainer devicesR3Dest   = p2p.Install(router3, dest);

    // [NEW] Node positions: horizontal chain matching the topology diagram
    SetupMobility(allNodes, {{10,50},{30,50},{50,50},{70,50},{90,50}});

    InternetStackHelper internet;
    internet.Install(allNodes);

    // =============================================================================
    // Relevant to [C]: IP Address Assignment (separate /24 per link)
    // Relevant to [B]: Source=10.1.1.1, Dest=10.1.4.2
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

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // =============================================================================
    // Relevant to [V]: PingHelper sends ICMP Echo Request packets.
    // Initial TTL=64 (ns-3 default); decrements to 61 when it reaches dest.
    // [NEW] jitter shifts start time so different seeds yield different timestamps.
    // =============================================================================
    PingHelper pingHelper(ifR3Dest.GetAddress(1)); // 10.1.4.2
    pingHelper.SetAttribute("Interval", TimeValue(Seconds(1.0)));
    pingHelper.SetAttribute("Size", UintegerValue(56));
    pingHelper.SetAttribute("VerboseMode", EnumValue(Ping::VERBOSE));
    ApplicationContainer pingApps = pingHelper.Install(source);
    pingApps.Start(Seconds(1.0 + jitter));
    pingApps.Stop(Seconds(10.0));

    // =============================================================================
    // Relevant to [W]: PCAP at every hop lets you compare TTL values.
    // client-0-0.pcap shows TTL=64; server-0-0.pcap shows TTL=61.
    // =============================================================================
    if (g_pcapEnabled)
    {
        p2p.EnablePcap(outputPath + "client",              devicesSourceR1.Get(0), true);
        p2p.EnablePcap(outputPath + "router1-to-client",   devicesSourceR1.Get(1), true);
        p2p.EnablePcap(outputPath + "router1-to-r2",       devicesR1R2.Get(0),     true);
        p2p.EnablePcap(outputPath + "router2-to-r1",       devicesR1R2.Get(1),     true);
        p2p.EnablePcap(outputPath + "router2-to-r3",       devicesR2R3.Get(0),     true);
        p2p.EnablePcap(outputPath + "router3-to-r2",       devicesR2R3.Get(1),     true);
        p2p.EnablePcap(outputPath + "router3-to-server",   devicesR3Dest.Get(0),   true);
        p2p.EnablePcap(outputPath + "server",              devicesR3Dest.Get(1),   true);
    }

    // [NEW] NetAnim output
    AnimationInterface anim(animFile);
    SetupNetAnim(anim, allNodes,
        {"Source\n10.1.1.1", "Router1\n10.1.1.2/10.1.2.1",
         "Router2\n10.1.2.2/10.1.3.1", "Router3\n10.1.3.2/10.1.4.1",
         "Dest\n10.1.4.2"},
        {{50,130,255},{255,165,0},{255,165,0},{255,165,0},{0,200,80}},
        12.0);

    Simulator::Stop(Seconds(12.0));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("Basic IPv4 Forwarding scenario complete.");
    NS_LOG_INFO("Hint: Compare TTL in client.pcap (64) vs server.pcap (61) - differs by 3 hops");
    NS_LOG_INFO("NetAnim: " << animFile);
}

// =============================================================================
// IPv4 FRAGMENTATION SCENARIO
// =============================================================================
// Relevant to [V]: IP fragmentation when datagram size > link MTU (Section 4.3.1)
//
// Relevant to [W]: Fragmentation visible in Wireshark via:
//   - Flags.MF=1 on all fragments except the last
//   - Fragment Offset non-zero on all except the first fragment
//   - Identification field identical across all fragments of one datagram
//   - Header Length (IHL) = 5 (20 bytes) - no options used
//
// Relevant to [C]: IP layer fragments automatically; application is unaware.
//
// [NEW] Experiment: vary --packetSize and --mtu to control fragmentation.
//   See experiment guide at bottom of file.
// =============================================================================

void RunFragmentationScenario(const std::string& outputPath,
                               const std::string& animFile,
                               double jitter)
{
    NS_LOG_INFO("=== Running IPv4 Fragmentation Scenario ===");
    NS_LOG_INFO("This scenario demonstrates IP fragmentation due to MTU constraints.");
    NS_LOG_INFO("Open client-0-0.pcap in Wireshark to see fragments.");

    NodeContainer nodes;
    nodes.Create(3);

    Ptr<Node> source = nodes.Get(0);
    Ptr<Node> router = nodes.Get(1);
    Ptr<Node> dest   = nodes.Get(2);

    // =============================================================================
    // Relevant to [C]: Source-side link uses g_mtu (default 1500 bytes)
    // Packet travels unfragmented on this link if packetSize <= mtu.
    // =============================================================================
    PointToPointHelper p2pLarge;
    p2pLarge.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2pLarge.SetChannelAttribute("Delay", StringValue("2ms"));
    p2pLarge.SetDeviceAttribute("Mtu", UintegerValue(g_mtu));

    NetDeviceContainer devicesSourceRouter = p2pLarge.Install(source, router);

    // =============================================================================
    // Relevant to [C]: Router-to-dest link MTU=576 (RFC 791 minimum IPv4 MTU).
    // Packets exceeding 576 bytes are fragmented here.
    //
    // Fragment payload per fragment = 576 - 20 (IP hdr) = 556 bytes
    // Must be multiple of 8: floor(556/8)*8 = 552 bytes payload per fragment
    // Number of fragments = ceil((g_packetSize + 8 UDP hdr) / 552)
    //
    // [NEW] The bottleneck MTU is always 576. Use --mtu to change the source link.
    //   Setting --mtu=576 makes both links the same; no fragmentation until
    //   the datagram itself exceeds 576 bytes (relevant to IHL question).
    // =============================================================================
    PointToPointHelper p2pSmall;
    p2pSmall.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2pSmall.SetChannelAttribute("Delay", StringValue("2ms"));
    p2pSmall.SetDeviceAttribute("Mtu", UintegerValue(576));

    NetDeviceContainer devicesRouterDest = p2pSmall.Install(router, dest);

    // [NEW] Node positions: horizontal chain
    SetupMobility(nodes, {{10,50},{50,50},{90,50}});

    InternetStackHelper internet;
    internet.Install(nodes);

    Ipv4AddressHelper address;

    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer ifSourceRouter = address.Assign(devicesSourceRouter);

    address.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer ifRouterDest = address.Assign(devicesRouterDest);

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    uint16_t serverPort = 5001;
    Address serverAddress(InetSocketAddress(ifRouterDest.GetAddress(1), serverPort));

    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory",
                                InetSocketAddress(Ipv4Address::GetAny(), serverPort));
    ApplicationContainer serverApp = sinkHelper.Install(dest);
    serverApp.Start(Seconds(0.0));
    serverApp.Stop(Seconds(30.0));

    // =============================================================================
    // Relevant to [C]: Application sends g_packetSize byte UDP datagrams.
    // IP layer adds 20-byte IP header + 8-byte UDP header on top.
    // If total > 576, IP fragments the datagram before forwarding.
    //
    // [NEW] g_packetSize configurable via --packetSize.
    // Try values just above and far above MTU for different fragment counts.
    // =============================================================================
    OnOffHelper clientHelper("ns3::UdpSocketFactory", serverAddress);
    clientHelper.SetAttribute("DataRate", StringValue("500kbps"));
    clientHelper.SetAttribute("PacketSize", UintegerValue(g_packetSize));
    clientHelper.SetAttribute("MaxBytes", UintegerValue(g_packetSize * 5));

    ApplicationContainer clientApp = clientHelper.Install(source);
    clientApp.Start(Seconds(1.0 + jitter));
    clientApp.Stop(Seconds(29.0));

    if (g_pcapEnabled)
    {
        p2pLarge.EnablePcap(outputPath + "client",              devicesSourceRouter.Get(0), true);
        p2pLarge.EnablePcap(outputPath + "router-from-client",  devicesSourceRouter.Get(1), true);
        p2pSmall.EnablePcap(outputPath + "router-to-server",    devicesRouterDest.Get(0),   true);
        p2pSmall.EnablePcap(outputPath + "server",              devicesRouterDest.Get(1),   true);
    }

    // [NEW] NetAnim output
    AnimationInterface anim(animFile);
    SetupNetAnim(anim, nodes,
        {"Source\n10.1.1.1\nMTU=" + std::to_string(g_mtu),
         "Router\n10.1.1.2/10.1.2.1\nbottleneck MTU=576",
         "Dest\n10.1.2.2"},
        {{50,130,255},{255,165,0},{0,200,80}},
        32.0);

    Simulator::Stop(Seconds(32.0));
    Simulator::Run();
    Simulator::Destroy();

    uint32_t totalBytes = g_packetSize + 8; // UDP header
    uint32_t fragsExpected = (totalBytes + 551) / 552; // ceil division
    NS_LOG_INFO("IPv4 Fragmentation scenario complete.");
    NS_LOG_INFO("Packet size (UDP payload): " << g_packetSize << " bytes");
    NS_LOG_INFO("Source-side MTU: " << g_mtu << ", bottleneck MTU: 576");
    NS_LOG_INFO("Expected fragments per datagram: ~" << fragsExpected);
    NS_LOG_INFO("Hint: Filter 'ip.flags.mf == 1 || ip.frag_offset > 0' in Wireshark");
    NS_LOG_INFO("NetAnim: " << animFile);
}

// =============================================================================
// ROUTING AND FORWARDING SCENARIO
// =============================================================================
// Relevant to [V]: Each router makes independent forwarding decision
// based on destination IP and routing table (Section 4.1)
//
// Relevant to [W]: Observe packet path through network by checking
// which interface captures contain ICMP traffic.
//
// Relevant to [C]: Global routing builds shortest-path routes automatically.
// =============================================================================

void RunRoutingScenario(const std::string& outputPath,
                         const std::string& animFile,
                         double jitter)
{
    NS_LOG_INFO("=== Running Routing and Forwarding Scenario ===");
    NS_LOG_INFO("This scenario demonstrates IP routing decisions.");
    NS_LOG_INFO("Open PCAPs to trace packet path through the network.");

    // =============================================================================
    // Relevant to [C]: Diamond topology - two equal-cost paths
    // Source -> Router1 -> Dest  (or)  Source -> Router2 -> Dest
    // =============================================================================
    NodeContainer nodes;
    nodes.Create(4);

    Ptr<Node> source  = nodes.Get(0);
    Ptr<Node> router1 = nodes.Get(1);
    Ptr<Node> router2 = nodes.Get(2);
    Ptr<Node> dest    = nodes.Get(3);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("2ms"));

    NetDeviceContainer devicesSourceR1 = p2p.Install(source,  router1);
    NetDeviceContainer devicesSourceR2 = p2p.Install(source,  router2);
    NetDeviceContainer devicesR1Dest   = p2p.Install(router1, dest);
    NetDeviceContainer devicesR2Dest   = p2p.Install(router2, dest);

    // [NEW] Diamond layout: Source left, Dest right, R1 top, R2 bottom
    SetupMobility(nodes, {{10,50},{50,80},{50,20},{90,50}});

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

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // Print and save routing tables
    Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper>(&std::cout);
    Ipv4GlobalRoutingHelper::PrintRoutingTableAllAt(Seconds(0.5), routingStream);

    std::ofstream routingFile(outputPath + "routing-tables.txt");
    Ptr<OutputStreamWrapper> fileStream = Create<OutputStreamWrapper>(&routingFile);
    Ipv4GlobalRoutingHelper::PrintRoutingTableAllAt(Seconds(0.5), fileStream);

    PingHelper pingHelper(ifR1Dest.GetAddress(1)); // 10.1.3.2
    pingHelper.SetAttribute("Interval", TimeValue(Seconds(1.0)));
    pingHelper.SetAttribute("Size", UintegerValue(56));
    pingHelper.SetAttribute("VerboseMode", EnumValue(Ping::VERBOSE));
    ApplicationContainer pingApps = pingHelper.Install(source);
    pingApps.Start(Seconds(1.0 + jitter));
    pingApps.Stop(Seconds(10.0));

    if (g_pcapEnabled)
    {
        p2p.EnablePcap(outputPath + "client-to-r1",       devicesSourceR1.Get(0), true);
        p2p.EnablePcap(outputPath + "client-to-r2",       devicesSourceR2.Get(0), true);
        p2p.EnablePcap(outputPath + "router1-from-client", devicesSourceR1.Get(1), true);
        p2p.EnablePcap(outputPath + "router2-from-client", devicesSourceR2.Get(1), true);
        p2p.EnablePcap(outputPath + "router1-to-server",  devicesR1Dest.Get(0),   true);
        p2p.EnablePcap(outputPath + "router2-to-server",  devicesR2Dest.Get(0),   true);
        p2p.EnablePcap(outputPath + "server-from-r1",     devicesR1Dest.Get(1),   true);
        p2p.EnablePcap(outputPath + "server-from-r2",     devicesR2Dest.Get(1),   true);
    }

    // [NEW] NetAnim output
    AnimationInterface anim(animFile);
    SetupNetAnim(anim, nodes,
        {"Source\n10.1.1.1", "Router1\n10.1.1.2/10.1.3.1",
         "Router2\n10.1.2.2/10.1.4.1", "Dest\n10.1.3.2/10.1.4.2"},
        {{50,130,255},{255,165,0},{255,165,0},{0,200,80}},
        12.0);

    Simulator::Stop(Seconds(12.0));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("Routing and Forwarding scenario complete.");
    NS_LOG_INFO("Routing tables saved to: " << outputPath << "routing-tables.txt");
    NS_LOG_INFO("Hint: Check which interface PCAPs contain ICMP traffic");
    NS_LOG_INFO("NetAnim: " << animFile);
}

// =============================================================================
// TTL EXPIRY SCENARIO (TRACEROUTE-STYLE)
// =============================================================================
// Relevant to [V]: TTL=0 -> router drops packet + sends ICMP Time Exceeded
// (Type 11, Code 0) back to source (Section 4.3.1)
//
// Relevant to [W]: Filter "icmp.type == 11" to see Time Exceeded messages.
// Each message originates from a different router, identifying each hop.
//
// Relevant to [C]: Low-TTL UDP packets simulate traceroute probes.
// TTL=1 expires at Router1; TTL=2 at Router2; TTL=3 at Router3; TTL=4 reaches dest.
// =============================================================================

void RunTtlExpiryScenario(const std::string& outputPath,
                           const std::string& animFile,
                           double jitter)
{
    NS_LOG_INFO("=== Running TTL Expiry Scenario ===");
    NS_LOG_INFO("This scenario demonstrates TTL expiry and ICMP Time Exceeded.");
    NS_LOG_INFO("Open client-0-0.pcap in Wireshark to see ICMP error messages.");

    NodeContainer allNodes;
    allNodes.Create(5);

    Ptr<Node> source  = allNodes.Get(0);
    Ptr<Node> router1 = allNodes.Get(1);
    Ptr<Node> router2 = allNodes.Get(2);
    Ptr<Node> router3 = allNodes.Get(3);
    Ptr<Node> dest    = allNodes.Get(4);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("2ms"));

    NetDeviceContainer devicesSourceR1 = p2p.Install(source,  router1);
    NetDeviceContainer devicesR1R2     = p2p.Install(router1, router2);
    NetDeviceContainer devicesR2R3     = p2p.Install(router2, router3);
    NetDeviceContainer devicesR3Dest   = p2p.Install(router3, dest);

    // [NEW] Node positions: horizontal chain
    SetupMobility(allNodes, {{10,50},{30,50},{50,50},{70,50},{90,50}});

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

    uint16_t serverPort = 5001;

    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory",
                                InetSocketAddress(Ipv4Address::GetAny(), serverPort));
    ApplicationContainer serverApp = sinkHelper.Install(dest);
    serverApp.Start(Seconds(0.0));
    serverApp.Stop(Seconds(30.0));

    // =============================================================================
    // Relevant to [C]: Four UDP probes with TTL = 1..4 simulate traceroute.
    // [NEW] jitter shifts all probes by the same small amount for reproducibility.
    // Socket TTL is set via SetIpTtl() before sending.
    // =============================================================================
    InetSocketAddress destAddr(ifR3Dest.GetAddress(1), serverPort);

    Ptr<Socket> socket1 = Socket::CreateSocket(source, UdpSocketFactory::GetTypeId());
    socket1->SetIpTtl(1);
    Simulator::Schedule(Seconds(1.0 + jitter), [socket1, destAddr]() {
        socket1->Connect(destAddr);
        socket1->Send(Create<Packet>(64));
        NS_LOG_INFO("Sent TTL=1 probe (expires at Router1)");
    });

    Ptr<Socket> socket2 = Socket::CreateSocket(source, UdpSocketFactory::GetTypeId());
    socket2->SetIpTtl(2);
    Simulator::Schedule(Seconds(2.0 + jitter), [socket2, destAddr]() {
        socket2->Connect(destAddr);
        socket2->Send(Create<Packet>(64));
        NS_LOG_INFO("Sent TTL=2 probe (expires at Router2)");
    });

    Ptr<Socket> socket3 = Socket::CreateSocket(source, UdpSocketFactory::GetTypeId());
    socket3->SetIpTtl(3);
    Simulator::Schedule(Seconds(3.0 + jitter), [socket3, destAddr]() {
        socket3->Connect(destAddr);
        socket3->Send(Create<Packet>(64));
        NS_LOG_INFO("Sent TTL=3 probe (expires at Router3)");
    });

    Ptr<Socket> socket4 = Socket::CreateSocket(source, UdpSocketFactory::GetTypeId());
    socket4->SetIpTtl(4);
    Simulator::Schedule(Seconds(4.0 + jitter), [socket4, destAddr]() {
        socket4->Connect(destAddr);
        socket4->Send(Create<Packet>(64));
        NS_LOG_INFO("Sent TTL=4 probe (reaches destination)");
    });

    if (g_pcapEnabled)
    {
        p2p.EnablePcap(outputPath + "client",  devicesSourceR1.Get(0), true);
        p2p.EnablePcap(outputPath + "router1", devicesSourceR1.Get(1), true);
        p2p.EnablePcap(outputPath + "router2", devicesR1R2.Get(1),     true);
        p2p.EnablePcap(outputPath + "router3", devicesR2R3.Get(1),     true);
        p2p.EnablePcap(outputPath + "server",  devicesR3Dest.Get(1),   true);
    }

    // [NEW] NetAnim output
    AnimationInterface anim(animFile);
    SetupNetAnim(anim, allNodes,
        {"Source\n10.1.1.1", "Router1\n10.1.1.2",
         "Router2\n10.1.2.2", "Router3\n10.1.3.2", "Dest\n10.1.4.2"},
        {{50,130,255},{255,165,0},{255,165,0},{255,165,0},{0,200,80}},
        10.0);

    Simulator::Stop(Seconds(10.0));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("TTL Expiry scenario complete.");
    NS_LOG_INFO("Hint: Filter 'icmp.type == 11' in Wireshark for Time Exceeded messages");
    NS_LOG_INFO("Hint: ICMP error source IP identifies the router at each hop");
    NS_LOG_INFO("NetAnim: " << animFile);
}

// =============================================================================
// MAIN FUNCTION
// =============================================================================

int main(int argc, char* argv[])
{
    std::string scenario = "all";
    bool verbose = false;
    int pcap = 1; // [NEW] PCAP on by default; pass --pcap=0 to disable

    CommandLine cmd(__FILE__);
    cmd.AddValue("scenario", "Scenario: basic-forwarding, fragmentation, routing, "
                             "ttl-expiry, all", scenario);
    cmd.AddValue("pcap",        "Enable PCAP capture (1=on [default], 0=off)", pcap);
    cmd.AddValue("verbose",     "Enable verbose logging", verbose);
    cmd.AddValue("packetSize",  "UDP payload size for fragmentation (bytes)", g_packetSize);
    cmd.AddValue("mtu",         "Source-link MTU for fragmentation scenario (bytes)", g_mtu);
    // [NEW] seed parameter
    cmd.AddValue("seed",        "RNG seed 1-100 (default 100)", g_seed);
    cmd.Parse(argc, argv);

    g_pcapEnabled = (pcap != 0);

    // =============================================================================
    // [NEW] Seed-based reproducibility.
    // RngSeedManager seeds the global RNG used by all stochastic components.
    // seedJitter: 0..0.095 s offset applied to packet send events; makes runs
    // with different seeds distinguishable in PCAP timestamps without changing
    // protocol behavior or breaking any lab question.
    // =============================================================================
    if (g_seed < 1)   g_seed = 1;
    if (g_seed > 100) g_seed = 100;
    RngSeedManager::SetSeed(g_seed);
    RngSeedManager::SetRun(g_seed);
    double seedJitter = (g_seed % 20) * 0.005; // 0.000 .. 0.095 s

    // =============================================================================
    // [NEW] PacketMetadata::Enable() must be called before any packets are created.
    // It instructs ns-3 to attach full protocol-stack descriptions to every packet
    // so AnimationInterface::EnablePacketMetadata(true) can write them to the XML.
    // Without this call, NetAnim arrows carry no protocol information.
    // =============================================================================
    PacketMetadata::Enable();

    if (verbose)
    {
        LogComponentEnable("IpLab", LOG_LEVEL_INFO);
        LogComponentEnable("Ipv4L3Protocol", LOG_LEVEL_INFO);
    }

    // Validate scenario
    std::vector<std::string> validScenarios = {
        "basic-forwarding", "fragmentation", "routing", "ttl-expiry", "all"
    };
    bool validScenario = false;
    for (const auto& s : validScenarios)
    {
        if (scenario == s) { validScenario = true; break; }
    }
    if (!validScenario)
    {
        std::cerr << "Invalid scenario: " << scenario << std::endl;
        return 1;
    }

    // =============================================================================
    // [NEW] Seed-namespaced output directory.
    // All PCAP and NetAnim files go under seed<N>/ so runs with different seeds
    // and different parameter values coexist without overwriting each other.
    // =============================================================================
    std::string seedDir = g_outputDir + "seed" + std::to_string(g_seed) + "/";

    std::cout << "=== ns-3 IP Lab ===" << std::endl;
    std::cout << "Scenario:   " << scenario   << std::endl;
    std::cout << "Seed:       " << g_seed     << "  (jitter=" << seedJitter << "s)" << std::endl;
    std::cout << "PacketSize: " << g_packetSize << " bytes" << std::endl;
    std::cout << "MTU:        " << g_mtu       << " bytes (source link)" << std::endl;
    std::cout << "PCAP:       " << (g_pcapEnabled ? "enabled" : "disabled") << std::endl;

    std::error_code ec;
    std::filesystem::create_directories(seedDir, ec);
    if (ec)
    {
        std::cerr << "Failed to create output directory: " << seedDir << std::endl;
        return 1;
    }

    // Helper lambda: creates and returns the per-scenario path
    auto makeOutputPath = [&](const std::string& sub) -> std::string {
        std::string path = (scenario == "all") ? seedDir + sub + "/" : seedDir;
        std::filesystem::create_directories(path, ec);
        return path;
    };

    // Helper lambda: NetAnim XML path for a scenario
    auto makeAnimFile = [&](const std::string& sub) -> std::string {
        return makeOutputPath(sub) + "netanim.xml";
    };

    bool success = true;

    if (scenario == "basic-forwarding" || scenario == "all")
    {
        std::string path = makeOutputPath("basic-forwarding");
        RunBasicForwardingScenario(path, makeAnimFile("basic-forwarding"), seedJitter);
        if (g_pcapEnabled)
            success = success && VerifyPcapFile(path + "client-0-0.pcap");
    }

    if (scenario == "fragmentation" || scenario == "all")
    {
        std::string path = makeOutputPath("fragmentation");
        RunFragmentationScenario(path, makeAnimFile("fragmentation"), seedJitter);
        if (g_pcapEnabled)
            success = success && VerifyPcapFile(path + "client-0-0.pcap");
    }

    if (scenario == "routing" || scenario == "all")
    {
        std::string path = makeOutputPath("routing");
        RunRoutingScenario(path, makeAnimFile("routing"), seedJitter);
        if (g_pcapEnabled)
            success = success && VerifyPcapFile(path + "client-to-r1-0-0.pcap");
    }

    if (scenario == "ttl-expiry" || scenario == "all")
    {
        std::string path = makeOutputPath("ttl-expiry");
        RunTtlExpiryScenario(path, makeAnimFile("ttl-expiry"), seedJitter);
        if (g_pcapEnabled)
            success = success && VerifyPcapFile(path + "client-0-0.pcap");
    }

    std::cout << std::endl;
    std::cout << "=== Simulation Complete ===" << std::endl;
    std::cout << "Output directory: " << seedDir << std::endl;
    std::cout << std::endl;
    std::cout << "=== Analysis Hints ===" << std::endl;
    std::cout << "- Basic Forwarding: Compare TTL in client.pcap (64) vs server.pcap (61)" << std::endl;
    std::cout << "- Fragmentation:    Filter 'ip.flags.mf == 1 || ip.frag_offset > 0'" << std::endl;
    std::cout << "- Routing:          Check which interface PCAPs contain ICMP traffic" << std::endl;
    std::cout << "- TTL Expiry:       Filter 'icmp.type == 11' for Time Exceeded" << std::endl;
    std::cout << "- NetAnim:          Open netanim.xml in each subfolder with NetAnim viewer" << std::endl;

    if (!g_pcapEnabled)
        std::cout << std::endl << "Note: PCAP disabled (--pcap=0). Re-run without --pcap=0 for Wireshark files." << std::endl;
    else if (!success)
    {
        std::cerr << "ERROR: One or more PCAP files failed verification!" << std::endl;
        return 1;
    }

    return 0;
}

/*
 * =============================================================================
 * PARAMETERIZED EXPERIMENT GUIDE
 * =============================================================================
 *
 * All commands below use --scenario=<name>.  Use --seed=N for reproducibility.
 * Output always goes to lab 3 output/seed<N>/.
 *
 * -----------------------------------------------------------------------------
 * 1. TTL BEHAVIOR ACROSS FORWARDING  (basic-forwarding + ttl-expiry)
 * -----------------------------------------------------------------------------
 * Question: Does TTL change as the packet traverses routers?
 *
 * There is no tunable input here - the behavior is structural (3 hops).
 * Use the pcap captures to observe TTL hop-by-hop:
 *
 *   ./ns3 run "... --scenario=basic-forwarding --seed=42"
 *
 * Wireshark:
 *   Open client-0-0.pcap:       ICMP Echo Request TTL = 64
 *   Open router1-to-r2-0-0.pcap: TTL = 63 (decremented once)
 *   Open router2-to-r3-0-0.pcap: TTL = 62 (decremented twice)
 *   Open server-0-0.pcap:        TTL = 61 (decremented three times)
 *
 * For ttl-expiry: observe that a packet with TTL=1 never reaches Router2.
 * The ICMP Time Exceeded (type 11) comes from Router1's IP (10.1.1.2).
 *
 *   ./ns3 run "... --scenario=ttl-expiry --seed=42"
 *   Wireshark filter: icmp.type == 11
 *   - First ICMP error: source=10.1.1.2 (Router1)
 *   - Second:           source=10.1.2.2 (Router2)
 *   - Third:            source=10.1.3.2 (Router3)
 *   - Fourth:           no error; packet reaches 10.1.4.2 (Dest)
 *
 * -----------------------------------------------------------------------------
 * 2. IPv4 FRAGMENTATION BEHAVIOR  (vary --packetSize and --mtu)
 * -----------------------------------------------------------------------------
 * Questions:
 *   - How many fragments? Which fields indicate fragmentation?
 *   - How to identify the last fragment? Why are offsets multiples of 8?
 *
 * The bottleneck link always has MTU=576.
 * Max IPv4 payload per fragment = 576 - 20 = 556 bytes.
 * Must be multiple of 8: floor(556/8)*8 = 552 bytes.
 * Fragments per datagram = ceil((packetSize + 8) / 552).
 *
 * Step 1 – No fragmentation (packetSize fits in one fragment):
 *   packetSize = 540  => payload + UDP hdr = 548 <= 552 => 1 fragment (no MF, offset=0)
 *   ./ns3 run "... --scenario=fragmentation --packetSize=540"
 *
 * Step 2 – Minimal fragmentation (just over one fragment):
 *   packetSize = 545  => 553 total => 2 fragments
 *   Fragment 1: 552 payload bytes, MF=1, offset=0
 *   Fragment 2: 1 payload byte,   MF=0, offset=69 (552/8=69)
 *   ./ns3 run "... --scenario=fragmentation --packetSize=545"
 *
 * Step 3 – Default (3500 bytes):
 *   total = 3508 => ceil(3508/552) = 7 fragments
 *   Fragment offsets: 0, 69, 138, 207, 276, 345, 414
 *   ./ns3 run "... --scenario=fragmentation --packetSize=3500"
 *
 * Step 4 – Large packet:
 *   packetSize = 8000 => total = 8008 => ceil(8008/552) = 15 fragments
 *   ./ns3 run "... --scenario=fragmentation --packetSize=8000"
 *
 * Varying --mtu (source-side link):
 *   --mtu=576   Source link same as bottleneck; packet is already fragmented
 *               before the router, so router-from-client.pcap shows fragments
 *   --mtu=9000  Jumbo frame source link; datagram travels whole to router,
 *               router fragments on the 576 MTU egress link
 *   ./ns3 run "... --scenario=fragmentation --packetSize=3500 --mtu=576"
 *   ./ns3 run "... --scenario=fragmentation --packetSize=3500 --mtu=9000"
 *
 * Wireshark analysis for fragmentation:
 *   Filter: ip.flags.mf == 1 || ip.frag_offset > 0
 *   - Identification field: same value on all fragments of one datagram
 *   - More Fragments (MF) bit: 1 on all except the LAST fragment
 *   - Fragment Offset: increments by (fragment_payload / 8) each fragment
 *   - Last fragment: MF=0, offset > 0
 *   - IHL: always 5 (20 bytes; no IP options used in this simulation)
 *   - Offset multiples of 8: mandated by RFC 791 to fit the 13-bit field
 *     (field stores offset/8; max offset = 8191 * 8 = 65528 bytes)
 *
 * Identify the last fragment:
 *   In Wireshark, click any fragment: IP Flags -> More Fragments.
 *   The frame where MF=0 AND Fragment Offset > 0 is the last fragment.
 *
 * Why offsets are multiples of 8:
 *   The Fragment Offset field is 13 bits wide (RFC 791).
 *   It stores the offset divided by 8, so any offset that is not
 *   a multiple of 8 cannot be represented. ns-3 respects this by using
 *   floor(556/8)*8 = 552 bytes per fragment payload. You can verify by
 *   computing 552/8 = 69 and checking Wireshark's offset column.
 * =============================================================================
 */
