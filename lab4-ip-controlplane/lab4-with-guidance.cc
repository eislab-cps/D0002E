/*
 * =============================================================================
 * ns-3 Wireshark Lab Simulation - Routing Algorithms (Link State & Distance Vector)
 * =============================================================================
 *
 * Lab 4: Network Layer - Routing Algorithms (Chapter 5)
 * File:  lab4update20260414.cc  (parameterised sweep edition)
 *
 * This script is a drop-in replacement for lab4-with-guidance.cc.
 * It adds:
 *   --seed          reproducible RNG seed (default 100)
 *   --r3r4Metric    cost of the R3-R4 link (default 10)
 *   --r2r4Metric    cost of the R2-R4 link (default 1)
 *   --lsaInterval   OSPF-like LSA flooding period in seconds (default 10)
 *   --failureTime   when the R2-R4 link is brought down, in seconds (default 40)
 *   --pingInterval  ICMP Echo Request interval in seconds (default 1)
 *   --ttlList       comma-separated TTL values for TTL-ICMP scenario (default 1,2,3,4,64)
 *
 * All existing commands continue to work unchanged.
 *
 * =============================================================================
 * HOW TO RUN
 * =============================================================================
 *
 * Build:
 *   ./ns3 build
 *
 * Basic runs (same as original script):
 *   ./ns3 run "scratch/d0002e/lab4update20260414 --scenario=lsdv --pcap=1"
 *   ./ns3 run "scratch/d0002e/lab4update20260414 --scenario=lsdv --mode=dv --pcap=1"
 *   ./ns3 run "scratch/d0002e/lab4update20260414 --scenario=ospf-like --pcap=1"
 *   ./ns3 run "scratch/d0002e/lab4update20260414 --scenario=ttl-icmp --pcap=1"
 *
 * Parameter sweep examples (add --seed=<group> for reproducibility):
 *
 *   # LS metric sweep: raise or lower R3-R4 cost (--mode=ls is the default)
 *   ./ns3 run "scratch/d0002e/lab4update20260414 --scenario=lsdv --r3r4Metric=5  --seed=42 --pcap=1"
 *   ./ns3 run "scratch/d0002e/lab4update20260414 --scenario=lsdv --r3r4Metric=20 --seed=42 --pcap=1"
 *   # NOTE: for DV mode keep r3r4Metric <= 12; higher values make the backup
 *   #       path unreachable (total metric >= RIP infinity of 16).
 *
 *   # Equal-cost tie-break: both paths cost 1
 *   ./ns3 run "scratch/d0002e/lab4update20260414 --scenario=lsdv --r3r4Metric=1 --r2r4Metric=1 --seed=42 --pcap=1"
 *
 *   # Failure-time sweep
 *   ./ns3 run "scratch/d0002e/lab4update20260414 --scenario=lsdv --failureTime=20 --seed=42 --pcap=1"
 *   ./ns3 run "scratch/d0002e/lab4update20260414 --scenario=lsdv --failureTime=60 --seed=42 --pcap=1"
 *
 *   # OSPF-like LSA interval sweep
 *   ./ns3 run "scratch/d0002e/lab4update20260414 --scenario=ospf-like --lsaInterval=5  --seed=42 --pcap=1"
 *   ./ns3 run "scratch/d0002e/lab4update20260414 --scenario=ospf-like --lsaInterval=30 --seed=42 --pcap=1"
 *
 *   # TTL sweep: single TTL value at a time
 *   ./ns3 run "scratch/d0002e/lab4update20260414 --scenario=ttl-icmp --ttlList=1 --seed=42 --pcap=1"
 *   ./ns3 run "scratch/d0002e/lab4update20260414 --scenario=ttl-icmp --ttlList=1,2,3 --seed=42 --pcap=1"
 *
 *   # Seed reproducibility: run twice with the same seed, compare output
 *   ./ns3 run "scratch/d0002e/lab4update20260414 --scenario=lsdv --seed=42 --pcap=1"
 *   ./ns3 run "scratch/d0002e/lab4update20260414 --scenario=lsdv --seed=99 --pcap=1"
 *
 * =============================================================================
 * NETWORK TOPOLOGY (LSDV and OSPF-like scenarios)
 * =============================================================================
 *
 *                 10.1.2.0/24         10.1.6.0/24
 *        [SRC]---[R1]---[R2]----------------[R4]---[DST]
 *                  \      |                  /
 *            10.1.3.0/24  |          10.1.5.0/24 (r3r4Metric)
 *                    \    | 10.1.4.0/24     /
 *                     \   |                 /
 *                      +--[R3]-------------+
 *
 *   Preferred path before failure: SRC->R1->R2->R4->DST  (if r2r4Metric < r3r4Metric)
 *   Backup path after failure:     SRC->R1->R3->R4->DST
 *   Equal-cost tie-break:          both paths active when r2r4Metric == r3r4Metric
 *   Link R2-R4 fails at t=failureTime seconds
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
 *   Packets with TTL=1,2,3 expire at R1,R2,R3 respectively
 *   Packets with TTL>=4 reach DST
 *
 * =============================================================================
 * PORT SELECTION
 * =============================================================================
 * Port 50001 is used for LSA messages (OSPF-like scenario).
 * Port 50002 is used for data traffic (TTL-ICMP scenario).
 * Port 9 (DISCARD) is intentionally avoided.
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
#include <stdexcept>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("RoutingLab");

// =============================================================================
// OUTPUT DIRECTORY
// =============================================================================
static std::string g_outputDir = "scratch/d0002e/lab 4 output/";

// =============================================================================
// PORT CONSTANTS
// =============================================================================
static const uint16_t LSA_PORT  = 50001;
static const uint16_t DATA_PORT = 50002;

// =============================================================================
// GLOBAL PCAP FLAG
// =============================================================================
static bool g_pcapEnabled = false;

// =============================================================================
// CONFIGURATION STRUCT
// =============================================================================
// Holds every tunable parameter so they do not need to be threaded through
// every function call individually.
// =============================================================================
struct LabConfig
{
    int         seed          = 100;
    std::string scenario      = "lsdv";
    std::string mode          = "ls";     // "ls" or "dv" for lsdv scenario
    int         pcap          = 0;
    bool        verbose       = false;
    int         r3r4Metric    = 10;       // cost of R3-R4 link
    int         r2r4Metric    = 1;        // cost of R2-R4 link
    double      lsaInterval   = 10.0;    // OSPF-like LSA period (seconds)
    double      failureTime   = 40.0;    // when R2-R4 link fails (seconds)
    double      pingInterval  = 1.0;     // ICMP Echo Request interval (seconds)
    std::string ttlList       = "1,2,3,4,64"; // comma-separated TTL values
};

// =============================================================================
// HELPER: Parse comma-separated TTL list
// =============================================================================
std::vector<uint32_t>
ParseTtlList(const std::string& s)
{
    std::vector<uint32_t> ttls;
    std::stringstream ss(s);
    std::string token;
    while (std::getline(ss, token, ','))
    {
        if (token.empty()) continue;
        int v = std::stoi(token);
        if (v <= 0)
        {
            std::cerr << "ERROR: TTL values must be positive integers (got " << v << ")" << std::endl;
            std::exit(1);
        }
        ttls.push_back(static_cast<uint32_t>(v));
    }
    if (ttls.empty())
    {
        std::cerr << "ERROR: --ttlList must contain at least one positive integer" << std::endl;
        std::exit(1);
    }
    return ttls;
}

// =============================================================================
// HELPER: Create output directory
// =============================================================================
void
EnsureDirectory(const std::string& path)
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
bool
VerifyPcapFile(const std::string& filepath)
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
// HELPER: Tear down link between two nodes (simulates link failure)
// =============================================================================
// Guidance for [C] questions: Brings both IPv4 interfaces to "down" state,
// triggering convergence in both LS (SPF recalculation) and DV (RIP updates).
// =============================================================================
void
TearDownLink(Ptr<Node> nodeA, Ptr<Node> nodeB, uint32_t interfaceA, uint32_t interfaceB)
{
    NS_LOG_INFO("=== LINK FAILURE at t=" << Simulator::Now().GetSeconds() << "s ===");
    nodeA->GetObject<Ipv4>()->SetDown(interfaceA);
    nodeB->GetObject<Ipv4>()->SetDown(interfaceB);
}

// =============================================================================
// HELPER: Write topology information to file
// =============================================================================
void
WriteTopologyInfo(const std::string& outputPath, const std::string& info)
{
    std::ofstream file(outputPath + "topology-info.txt");
    file << info;
    file.close();
    std::cout << "Topology info written to: " << outputPath << "topology-info.txt" << std::endl;
}

// =============================================================================
// HELPER: Print effective configuration to stdout
// =============================================================================
void
PrintEffectiveConfig(const LabConfig& cfg)
{
    std::cout << "--- Effective parameters ---" << std::endl;
    std::cout << "  seed         = " << cfg.seed         << std::endl;
    std::cout << "  scenario     = " << cfg.scenario     << std::endl;
    if (cfg.scenario == "lsdv")
    {
        std::cout << "  mode         = " << cfg.mode         << std::endl;
        std::cout << "  r3r4Metric   = " << cfg.r3r4Metric   << std::endl;
        std::cout << "  r2r4Metric   = " << cfg.r2r4Metric   << std::endl;
        std::cout << "  failureTime  = " << cfg.failureTime  << " s" << std::endl;
        std::cout << "  pingInterval = " << cfg.pingInterval << " s" << std::endl;
        if (cfg.r3r4Metric == cfg.r2r4Metric)
        {
            std::cout << "  NOTE: r3r4Metric == r2r4Metric -> equal-cost paths, "
                         "observe tie-break behaviour" << std::endl;
        }
    }
    if (cfg.scenario == "ospf-like")
    {
        std::cout << "  lsaInterval  = " << cfg.lsaInterval  << " s" << std::endl;
    }
    if (cfg.scenario == "ttl-icmp")
    {
        std::cout << "  ttlList      = " << cfg.ttlList      << std::endl;
    }
    std::cout << "  pcap         = " << cfg.pcap         << std::endl;
    std::cout << "----------------------------" << std::endl;
}

// =============================================================================
// =============================================================================
// SCENARIO 1: LINK STATE vs DISTANCE VECTOR (LSDV)
// =============================================================================
// =============================================================================
//
// Guidance for [C]/[B] questions:
//   LS mode  - Ipv4GlobalRoutingHelper (Dijkstra, global view)
//   DV mode  - RipHelper (Bellman-Ford, distributed)
//
// Wireshark hints:
//   - Filter "rip" for RIP updates (DV mode)
//   - Filter "icmp" for ping traffic
//   - Observe routing-tables.txt for convergence comparison
//
// New parameters used here:
//   cfg.r3r4Metric  - cost of the backup R3-R4 link
//   cfg.r2r4Metric  - cost of the preferred R2-R4 link (default 1)
//   cfg.failureTime - when R2-R4 is brought down
//   cfg.pingInterval - ICMP Echo Request interval
//   cfg.seed        - controls timing jitter (reproducible)
// =============================================================================

void
RunLsdvScenario(const std::string& outputPath, bool useLinkState, const LabConfig& cfg)
{
    std::string modeStr = useLinkState ? "Link State (GlobalRouting)" : "Distance Vector (RIP)";
    NS_LOG_INFO("=== Running LSDV Scenario - " << modeStr << " ===");

    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "LSDV Scenario: " << modeStr << std::endl;
    std::cout << "========================================" << std::endl;

    // =========================================================================
    // Seed-driven jitter for ping start time.
    // Small bounded offset keeps results reproducible for the same seed while
    // making different seeds produce slightly different packet timestamps.
    // Route selection is NOT affected by the jitter.
    // =========================================================================
    Ptr<UniformRandomVariable> jitter = CreateObject<UniformRandomVariable>();
    jitter->SetAttribute("Min", DoubleValue(0.0));
    jitter->SetAttribute("Max", DoubleValue(0.5));  // max 500 ms offset
    double pingJitter = jitter->GetValue();

    // =========================================================================
    // Guidance for [C] questions: Node Creation
    // Two endpoints (SRC, DST) and four routers (R1-R4).
    // =========================================================================
    NodeContainer routers;
    NodeContainer endpoints;
    Ptr<Node> src = CreateObject<Node>();
    Ptr<Node> r1  = CreateObject<Node>();
    Ptr<Node> r2  = CreateObject<Node>();
    Ptr<Node> r3  = CreateObject<Node>();
    Ptr<Node> r4  = CreateObject<Node>();
    Ptr<Node> dst = CreateObject<Node>();

    Names::Add("SRC", src);
    Names::Add("R1",  r1);
    Names::Add("R2",  r2);
    Names::Add("R3",  r3);
    Names::Add("R4",  r4);
    Names::Add("DST", dst);

    routers.Add(r1); routers.Add(r2); routers.Add(r3); routers.Add(r4);
    endpoints.Add(src); endpoints.Add(dst);
    NodeContainer allNodes(src, r1, r2, r3, r4, dst);

    NodeContainer linkSrcR1(src, r1);
    NodeContainer linkR1R2(r1, r2);
    NodeContainer linkR1R3(r1, r3);
    NodeContainer linkR2R3(r2, r3);
    NodeContainer linkR3R4(r3, r4);
    NodeContainer linkR2R4(r2, r4);
    NodeContainer linkR4Dst(r4, dst);

    // =========================================================================
    // Guidance for [C] questions: Channel creation (CSMA / Ethernet-like)
    // =========================================================================
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", DataRateValue(DataRate("100Mbps")));
    csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));

    NetDeviceContainer devSrcR1 = csma.Install(linkSrcR1);
    NetDeviceContainer devR1R2  = csma.Install(linkR1R2);
    NetDeviceContainer devR1R3  = csma.Install(linkR1R3);
    NetDeviceContainer devR2R3  = csma.Install(linkR2R3);
    NetDeviceContainer devR3R4  = csma.Install(linkR3R4);
    NetDeviceContainer devR2R4  = csma.Install(linkR2R4);
    NetDeviceContainer devR4Dst = csma.Install(linkR4Dst);

    // =========================================================================
    // Guidance for [C]/[B] questions: Routing protocol selection
    //
    // LS mode  - GlobalRouting with RespondToInterfaceEvents=true
    //            Recomputes shortest paths via Dijkstra on topology changes.
    //
    // DV mode  - RIP with per-interface metrics.
    //            r3r4Metric (default 10) makes R3-R4 the backup path.
    //            r2r4Metric (default 1) keeps R2-R4 as the preferred path.
    //            When r2r4Metric == r3r4Metric both paths are equal-cost.
    // =========================================================================
    InternetStackHelper internet;
    internet.SetIpv6StackInstall(false);

    if (useLinkState)
    {
        Config::SetDefault("ns3::Ipv4GlobalRouting::RespondToInterfaceEvents",
                           BooleanValue(true));
        internet.Install(allNodes);
    }
    else
    {
        // =====================================================================
        // Guidance for [C]/[B] questions: RIP interface metrics
        //
        // ExcludeInterface: prevents RIP from advertising those subnets
        //   r1 iface 1 = SRC-R1 link (static, not advertised by RIP)
        //   r4 iface 3 = R4-DST link (static, not advertised by RIP)
        //
        // SetInterfaceMetric: sets per-hop cost for Bellman-Ford computation
        //   r3r4Metric (default 10) -> R3-R4 path costs more -> R2-R4 preferred
        //   r2r4Metric (default 1)  -> R2-R4 path costs less -> preferred path
        //
        //   Path costs (SRC to DST):
        //     via R2: 1 + 1 + r2r4Metric + 1
        //     via R3: 1 + 1 + r3r4Metric + 1
        //   R2 path is preferred when r2r4Metric < r3r4Metric.
        //   Equal-cost when r2r4Metric == r3r4Metric.
        //   R3 path preferred when r2r4Metric > r3r4Metric.
        //
        // The same logic applies in LS mode via ifR3R4.SetMetric / ifR2R4.SetMetric
        // below, which sets interface costs for Dijkstra's algorithm.
        // =====================================================================
        RipHelper ripRouting;
        ripRouting.ExcludeInterface(r1, 1);
        ripRouting.ExcludeInterface(r4, 3);
        ripRouting.SetInterfaceMetric(r3, 3, cfg.r3r4Metric);  // r3 iface 3 = to R4 (10.1.5.x)
        ripRouting.SetInterfaceMetric(r4, 1, cfg.r3r4Metric);  // r4 iface 1 = to R3 (10.1.5.x)
        ripRouting.SetInterfaceMetric(r2, 3, cfg.r2r4Metric);  // r2 iface 3 = to R4 (10.1.6.x)
        ripRouting.SetInterfaceMetric(r4, 2, cfg.r2r4Metric);  // r4 iface 2 = to R2 (10.1.6.x)

        Ipv4ListRoutingHelper listRH;
        listRH.Add(ripRouting, 0);
        internet.SetRoutingHelper(listRH);
        internet.Install(routers);

        InternetStackHelper internetEndpoints;
        internetEndpoints.SetIpv6StackInstall(false);
        internetEndpoints.Install(endpoints);
    }

    // =========================================================================
    // Guidance for [C]/[B] questions: IP address assignment
    // Each link is a /24 subnet.  These addresses appear in Wireshark headers.
    // =========================================================================
    Ipv4AddressHelper ipv4;

    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer ifSrcR1 = ipv4.Assign(devSrcR1);

    ipv4.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer ifR1R2  = ipv4.Assign(devR1R2);

    ipv4.SetBase("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer ifR1R3  = ipv4.Assign(devR1R3);

    ipv4.SetBase("10.1.4.0", "255.255.255.0");
    Ipv4InterfaceContainer ifR2R3  = ipv4.Assign(devR2R3);

    ipv4.SetBase("10.1.5.0", "255.255.255.0");
    Ipv4InterfaceContainer ifR3R4  = ipv4.Assign(devR3R4);

    ipv4.SetBase("10.1.6.0", "255.255.255.0");
    Ipv4InterfaceContainer ifR2R4  = ipv4.Assign(devR2R4);

    ipv4.SetBase("10.1.7.0", "255.255.255.0");
    Ipv4InterfaceContainer ifR4Dst = ipv4.Assign(devR4Dst);

    // =========================================================================
    // Guidance for [C]/[W+X] questions: Interface metrics for LS mode
    // Ipv4GlobalRouting reads these per-interface costs during Dijkstra.
    // Changing r3r4Metric and r2r4Metric here shifts which path is preferred.
    //   Default: r2r4Metric=1, r3r4Metric=10 -> R2-R4 path preferred.
    //   To make R3-R4 preferred, set r2r4Metric > r3r4Metric
    //     (e.g. --r2r4Metric=15 --r3r4Metric=5).
    //   To get equal-cost ECMP, set r2r4Metric == r3r4Metric.
    // =========================================================================
    ifR3R4.SetMetric(0, cfg.r3r4Metric);  // R3's interface toward R4
    ifR3R4.SetMetric(1, cfg.r3r4Metric);  // R4's interface toward R3
    ifR2R4.SetMetric(0, cfg.r2r4Metric);  // R2's interface toward R4
    ifR2R4.SetMetric(1, cfg.r2r4Metric);  // R4's interface toward R2

    if (useLinkState)
    {
        Ipv4GlobalRoutingHelper::PopulateRoutingTables();
    }
    else
    {
        Ptr<Ipv4StaticRouting> staticRouting;
        staticRouting = Ipv4RoutingHelper::GetRouting<Ipv4StaticRouting>(
            src->GetObject<Ipv4>()->GetRoutingProtocol());
        staticRouting->SetDefaultRoute("10.1.1.2", 1);

        staticRouting = Ipv4RoutingHelper::GetRouting<Ipv4StaticRouting>(
            dst->GetObject<Ipv4>()->GetRoutingProtocol());
        staticRouting->SetDefaultRoute("10.1.7.1", 1);
    }

    // =========================================================================
    // Guidance for [C]/[B] questions: Ping application
    // Sends ICMP Echo Requests from SRC to DST.
    // pingInterval is parameterised; start time has small seed-driven jitter.
    // =========================================================================
    double pingStart = 5.0 + pingJitter;
    double simEnd    = std::max(95.0, cfg.failureTime + 55.0);
    double pingStop  = simEnd - 5.0;

    PingHelper ping(ifR4Dst.GetAddress(1));
    ping.SetAttribute("Interval", TimeValue(Seconds(cfg.pingInterval)));
    ping.SetAttribute("Size", UintegerValue(64));
    ping.SetAttribute("VerboseMode", EnumValue(Ping::VerboseMode::VERBOSE));

    ApplicationContainer pingApp = ping.Install(src);
    pingApp.Start(Seconds(pingStart));
    pingApp.Stop(Seconds(pingStop));

    // =========================================================================
    // Guidance for [C]/[B] questions: Link failure event
    // R2's interface to R4 is index 3; R4's interface to R2 is index 2.
    // failureTime is parameterised (default 40 s).
    //   - LS: triggers immediate SPF recalculation -> fast convergence
    //   - DV: triggers RIP count-to-infinity / split horizon -> slower convergence
    // =========================================================================
    NS_LOG_INFO("Scheduling link failure at t=" << cfg.failureTime << "s");
    Simulator::Schedule(Seconds(cfg.failureTime), &TearDownLink, r2, r4, 3, 2);

    // =========================================================================
    // Routing table snapshots for convergence analysis
    // =========================================================================
    Ptr<OutputStreamWrapper> routingStream =
        Create<OutputStreamWrapper>(outputPath + "routing-tables.txt", std::ios::out);

    Ipv4RoutingHelper::PrintRoutingTableAllAt(Seconds(10), routingStream);
    Ipv4RoutingHelper::PrintRoutingTableAllAt(
        Seconds(std::max(11.0, cfg.failureTime - 5.0)), routingStream);
    Ipv4RoutingHelper::PrintRoutingTableAllAt(
        Seconds(cfg.failureTime + 5.0), routingStream);
    Ipv4RoutingHelper::PrintRoutingTableAllAt(
        Seconds(cfg.failureTime + 20.0), routingStream);
    Ipv4RoutingHelper::PrintRoutingTableAllAt(
        Seconds(cfg.failureTime + 40.0), routingStream);

    // =========================================================================
    // PCAP capture
    // Wireshark filters:
    //   "rip"  - RIP update messages (DV mode)
    //   "icmp" - ICMP ping traffic
    // =========================================================================
    if (g_pcapEnabled)
    {
        csma.EnablePcap(outputPath + "lsdv-src-r1", devSrcR1.Get(0), true);
        csma.EnablePcap(outputPath + "lsdv-r1-r2",  devR1R2.Get(0),  true);
        csma.EnablePcap(outputPath + "lsdv-r1-r3",  devR1R3.Get(0),  true);
        csma.EnablePcap(outputPath + "lsdv-r2-r3",  devR2R3.Get(0),  true);
        csma.EnablePcap(outputPath + "lsdv-r3-r4",  devR3R4.Get(0),  true);
        csma.EnablePcap(outputPath + "lsdv-r2-r4",  devR2R4.Get(0),  true);
        csma.EnablePcap(outputPath + "lsdv-r4-dst",  devR4Dst.Get(0), true);
    }

    // Topology info with effective parameter values
    std::stringstream topoInfo;
    topoInfo << "LSDV Scenario Topology - " << modeStr << "\n";
    topoInfo << "=========================================\n\n";
    topoInfo << "Effective parameters:\n";
    topoInfo << "  seed          = " << cfg.seed         << "\n";
    topoInfo << "  r3r4Metric    = " << cfg.r3r4Metric   << "\n";
    topoInfo << "  r2r4Metric    = " << cfg.r2r4Metric   << "\n";
    topoInfo << "  failureTime   = " << cfg.failureTime  << " s\n";
    topoInfo << "  pingInterval  = " << cfg.pingInterval << " s\n";
    if (cfg.r3r4Metric == cfg.r2r4Metric)
    {
        topoInfo << "  NOTE: equal-cost paths (tie-break experiment)\n";
    }
    topoInfo << "\nNodes:\n";
    topoInfo << "  SRC: 10.1.1.1\n";
    topoInfo << "  R1:  10.1.1.2, 10.1.2.1, 10.1.3.1\n";
    topoInfo << "  R2:  10.1.2.2, 10.1.4.1, 10.1.6.1\n";
    topoInfo << "  R3:  10.1.3.2, 10.1.4.2, 10.1.5.1\n";
    topoInfo << "  R4:  10.1.5.2, 10.1.6.2, 10.1.7.1\n";
    topoInfo << "  DST: 10.1.7.2\n\n";
    topoInfo << "Links:\n";
    topoInfo << "  SRC-R1: 10.1.1.0/24 (metric 1)\n";
    topoInfo << "  R1-R2:  10.1.2.0/24 (metric 1)\n";
    topoInfo << "  R1-R3:  10.1.3.0/24 (metric 1)\n";
    topoInfo << "  R2-R3:  10.1.4.0/24 (metric 1)\n";
    topoInfo << "  R3-R4:  10.1.5.0/24 (metric " << cfg.r3r4Metric << ")\n";
    topoInfo << "  R2-R4:  10.1.6.0/24 (metric " << cfg.r2r4Metric
             << ", FAILS at t=" << cfg.failureTime << "s)\n";
    topoInfo << "  R4-DST: 10.1.7.0/24 (metric 1)\n\n";
    topoInfo << "Events:\n";
    topoInfo << "  t=" << pingStart << "s: Ping starts (SRC->10.1.7.2)\n";
    topoInfo << "  t=" << cfg.failureTime << "s: R2-R4 link fails\n";
    topoInfo << "  t=" << simEnd << "s: Simulation ends\n";
    WriteTopologyInfo(outputPath, topoInfo.str());

    Simulator::Stop(Seconds(simEnd));
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
// IMPORTANT: This is an instructional approximation, NOT a full OSPF
// implementation.  ns-3's basic internet module does not include OSPF.
//
// Guidance for [C]/[B] questions:
//   - LsaApplication sends periodic LSAs on UDP port 50001
//   - lsaInterval is parameterised (default 10 s)
//   - Each router floods LSAs to both neighbours in the triangle topology
//
// Wireshark hints:
//   - Filter "udp.port==50001" for LSA packets
//   - Observe LSA flooding period (equals lsaInterval)
//   - LSA payload: RouterID, SeqNo, neighbour list
//
// New parameter used here:
//   cfg.lsaInterval  - LSA flooding period (default 10 s)
//   cfg.seed         - controls per-router LSA start jitter (reproducible)
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
        m_routerId  = routerId;
        m_interval  = interval;
    }

  private:
    virtual void StartApplication() override
    {
        m_running = true;
        m_socket  = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        m_socket->Bind();
        SendLsa();
    }

    virtual void StopApplication() override
    {
        m_running = false;
        if (m_socket) m_socket->Close();
    }

    void SendLsa()
    {
        if (!m_running) return;

        // =====================================================================
        // Guidance for [C]/[B] questions: LSA packet format
        //   RouterID | SeqNo | neighbour count | neighbour addresses
        // This mimics a simplified OSPF LSA.
        // =====================================================================
        std::stringstream lsaData;
        lsaData << "LSA|RouterID=" << m_routerId
                << "|Seq=" << m_sequenceNumber
                << "|Neighbors=" << m_neighbors.size();
        for (const auto& n : m_neighbors)
            lsaData << "|" << n;

        std::string lsaStr = lsaData.str();
        Ptr<Packet> packet = Create<Packet>((uint8_t*)lsaStr.c_str(), lsaStr.length());

        for (const auto& n : m_neighbors)
            m_socket->SendTo(packet, 0, InetSocketAddress(n, LSA_PORT));

        NS_LOG_INFO("Router " << m_routerId << " LSA seq=" << m_sequenceNumber
                              << " -> " << m_neighbors.size() << " neighbours");
        m_sequenceNumber++;

        Simulator::Schedule(m_interval, &LsaApplication::SendLsa, this);
    }

    Ptr<Socket>              m_socket;
    std::vector<Ipv4Address> m_neighbors;
    uint32_t                 m_routerId;
    Time                     m_interval;
    bool                     m_running;
    uint32_t                 m_sequenceNumber;
};

void
RunOspfLikeScenario(const std::string& outputPath, const LabConfig& cfg)
{
    NS_LOG_INFO("=== Running OSPF-Like Scenario ===");

    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "OSPF-Like LSA Flooding Scenario" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "NOTE: Instructional OSPF approximation." << std::endl;
    std::cout << "LSA port: " << LSA_PORT << " | interval: " << cfg.lsaInterval << "s" << std::endl;

    // =========================================================================
    // Seed-driven jitter for LSA start offsets.
    // Different seeds shift when each router first floods its LSA, producing
    // slightly different packet timestamps without changing the topology or
    // the steady-state flooding behaviour.
    // =========================================================================
    Ptr<UniformRandomVariable> jitter = CreateObject<UniformRandomVariable>();
    jitter->SetAttribute("Min", DoubleValue(0.0));
    jitter->SetAttribute("Max", DoubleValue(0.5));

    double j1 = jitter->GetValue();   // R1 start offset
    double j2 = jitter->GetValue();   // R2 start offset
    double j3 = jitter->GetValue();   // R3 start offset

    // =========================================================================
    // Triangle topology: R1 -- R2 -- R3 -- R1
    // =========================================================================
    NodeContainer routers;
    routers.Create(3);
    Names::Add("R1", routers.Get(0));
    Names::Add("R2", routers.Get(1));
    Names::Add("R3", routers.Get(2));

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("2ms"));

    NetDeviceContainer devR1R2 = p2p.Install(routers.Get(0), routers.Get(1));
    NetDeviceContainer devR2R3 = p2p.Install(routers.Get(1), routers.Get(2));
    NetDeviceContainer devR3R1 = p2p.Install(routers.Get(2), routers.Get(0));

    InternetStackHelper internet;
    internet.Install(routers);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.0.1.0", "255.255.255.0");
    Ipv4InterfaceContainer ifR1R2 = ipv4.Assign(devR1R2);
    ipv4.SetBase("10.0.2.0", "255.255.255.0");
    Ipv4InterfaceContainer ifR2R3 = ipv4.Assign(devR2R3);
    ipv4.SetBase("10.0.3.0", "255.255.255.0");
    Ipv4InterfaceContainer ifR3R1 = ipv4.Assign(devR3R1);

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // =========================================================================
    // Guidance for [C]/[B] questions: LSA application setup
    // Each router periodically floods LSAs to its two direct neighbours.
    // lsaInterval controls the flooding period (parameterised).
    // =========================================================================
    Time interval = Seconds(cfg.lsaInterval);
    // simEnd is fixed so that changing lsaInterval changes the *rate* of LSA
    // floods seen in Wireshark, not the total number.  With a fixed 65 s window:
    //   lsaInterval=5  -> ~12 floods per router  (~24 packets on each link)
    //   lsaInterval=10 -> ~6  floods per router  (~12 packets on each link)
    //   lsaInterval=30 -> ~2  floods per router  (~4  packets on each link)
    // Students can compare the inter-packet time gap in Wireshark to answer Q7.
    double simEnd = 65.0;

    // R1: neighbours are R2 (10.0.1.2) and R3-side of R3R1 (10.0.3.1)
    Ptr<LsaApplication> lsaR1 = CreateObject<LsaApplication>();
    lsaR1->Setup({ifR1R2.GetAddress(1), ifR3R1.GetAddress(0)}, 1, interval);
    routers.Get(0)->AddApplication(lsaR1);
    lsaR1->SetStartTime(Seconds(1.0 + j1));
    lsaR1->SetStopTime(Seconds(simEnd - 5.0));

    // R2: neighbours are R1 (10.0.1.1) and R3 (10.0.2.2)
    Ptr<LsaApplication> lsaR2 = CreateObject<LsaApplication>();
    lsaR2->Setup({ifR1R2.GetAddress(0), ifR2R3.GetAddress(1)}, 2, interval);
    routers.Get(1)->AddApplication(lsaR2);
    lsaR2->SetStartTime(Seconds(2.0 + j2));
    lsaR2->SetStopTime(Seconds(simEnd - 5.0));

    // R3: neighbours are R2 (10.0.2.1) and R1-side of R3R1 (10.0.3.2)
    Ptr<LsaApplication> lsaR3 = CreateObject<LsaApplication>();
    lsaR3->Setup({ifR2R3.GetAddress(0), ifR3R1.GetAddress(1)}, 3, interval);
    routers.Get(2)->AddApplication(lsaR3);
    lsaR3->SetStartTime(Seconds(3.0 + j3));
    lsaR3->SetStopTime(Seconds(simEnd - 5.0));

    // =========================================================================
    // Guidance for [C] questions: UDP sink on each router (LSA receiver)
    // Each router listens on LSA_PORT (50001) so incoming LSA packets are
    // silently consumed rather than generating ICMP Port Unreachable replies.
    // Without this, the kernel returns ICMP Type 3 (Destination Unreachable)
    // for every received LSA, since there is no socket bound to port 50001.
    //
    // Real OSPF avoids this entirely by using IP protocol 89 directly, without
    // a transport layer. Here we use UDP for simplicity and add a sink to keep
    // the PCAP clean. Students filtering "udp.port==50001" will see only LSA
    // floods, not ICMP errors.
    // =========================================================================
    PacketSinkHelper lsaSink("ns3::UdpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), LSA_PORT));
    ApplicationContainer sinkApps = lsaSink.Install(routers);
    sinkApps.Start(Seconds(0));
    sinkApps.Stop(Seconds(simEnd));

    // =========================================================================
    // PCAP capture
    // Wireshark filter: "udp.port==50001"  -> shows only LSA floods
    // =========================================================================
    if (g_pcapEnabled)
    {
        p2p.EnablePcap(outputPath + "ospf-like-r1r2", devR1R2.Get(0), true);
        p2p.EnablePcap(outputPath + "ospf-like-r2r3", devR2R3.Get(0), true);
        p2p.EnablePcap(outputPath + "ospf-like-r3r1", devR3R1.Get(0), true);
    }

    std::stringstream topoInfo;
    topoInfo << "OSPF-Like Scenario Topology\n";
    topoInfo << "=========================================\n\n";
    topoInfo << "NOTE: Instructional OSPF approximation.\n";
    topoInfo << "LSA port: " << LSA_PORT << " (not DISCARD port 9)\n\n";
    topoInfo << "Effective parameters:\n";
    topoInfo << "  seed        = " << cfg.seed         << "\n";
    topoInfo << "  lsaInterval = " << cfg.lsaInterval  << " s\n\n";
    topoInfo << "Triangle Topology:\n";
    topoInfo << "        R1\n";
    topoInfo << "       /  \\\n";
    topoInfo << "      /    \\\n";
    topoInfo << "     R3----R2\n\n";
    topoInfo << "IP Addresses:\n";
    topoInfo << "  R1-R2: 10.0.1.0/24 (R1=.1, R2=.2)\n";
    topoInfo << "  R2-R3: 10.0.2.0/24 (R2=.1, R3=.2)\n";
    topoInfo << "  R3-R1: 10.0.3.0/24 (R3=.1, R1=.2)\n\n";
    topoInfo << "LSA Flooding:\n";
    topoInfo << "  Interval: " << cfg.lsaInterval << " s\n";
    topoInfo << "  Each router floods to 2 neighbours\n\n";
    topoInfo << "Wireshark filter: udp.port==" << LSA_PORT << "\n";
    WriteTopologyInfo(outputPath, topoInfo.str());

    Simulator::Stop(Seconds(simEnd));
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
//   - Each router decrements TTL by 1
//   - TTL=0: router drops packet and sends ICMP Time Exceeded (Type 11, Code 0)
//   - Socket::SetIpTtl() sets the initial TTL value
//
// Wireshark hints:
//   - Filter "icmp.type==11" for Time Exceeded messages
//   - ICMP payload includes copy of original IP header + first 8 data bytes
//   - Source IP of ICMP reply identifies the router that dropped the packet
//
// New parameter used here:
//   cfg.ttlList  - comma-separated list of TTL values to test
//                  default "1,2,3,4,64" reproduces original behaviour
//   cfg.seed     - controls small timing jitter on send events (reproducible)
// =============================================================================

void
RunTtlIcmpScenario(const std::string& outputPath, const LabConfig& cfg)
{
    NS_LOG_INFO("=== Running TTL-ICMP Scenario ===");

    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "TTL Expiry and ICMP Time Exceeded" << std::endl;
    std::cout << "========================================" << std::endl;

    std::vector<uint32_t> ttls = ParseTtlList(cfg.ttlList);

    // =========================================================================
    // Linear topology: SRC -- R1 -- R2 -- R3 -- DST (4 hops)
    //   TTL=1 expires at R1, TTL=2 at R2, TTL=3 at R3, TTL>=4 reaches DST
    // =========================================================================
    NodeContainer allNodes;
    allNodes.Create(5);

    Ptr<Node> src = allNodes.Get(0);
    Ptr<Node> r1  = allNodes.Get(1);
    Ptr<Node> r2  = allNodes.Get(2);
    Ptr<Node> r3  = allNodes.Get(3);
    Ptr<Node> dst = allNodes.Get(4);

    Names::Add("SRC-TTL", src);
    Names::Add("R1-TTL",  r1);
    Names::Add("R2-TTL",  r2);
    Names::Add("R3-TTL",  r3);
    Names::Add("DST-TTL", dst);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("2ms"));

    NetDeviceContainer devSrcR1 = p2p.Install(src, r1);
    NetDeviceContainer devR1R2  = p2p.Install(r1, r2);
    NetDeviceContainer devR2R3  = p2p.Install(r2, r3);
    NetDeviceContainer devR3Dst = p2p.Install(r3, dst);

    InternetStackHelper internet;
    internet.Install(allNodes);

    // =========================================================================
    // Guidance for [C]/[B] questions: IP address assignment
    // These addresses appear in the ICMP Time Exceeded source field.
    // =========================================================================
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    ipv4.Assign(devSrcR1);
    ipv4.SetBase("10.1.2.0", "255.255.255.0");
    ipv4.Assign(devR1R2);
    ipv4.SetBase("10.1.3.0", "255.255.255.0");
    ipv4.Assign(devR2R3);
    ipv4.SetBase("10.1.4.0", "255.255.255.0");
    Ipv4InterfaceContainer ifR3Dst = ipv4.Assign(devR3Dst);

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // UDP server at DST (receives packets that survive the full path)
    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory",
                                InetSocketAddress(Ipv4Address::GetAny(), DATA_PORT));
    ApplicationContainer serverApp = sinkHelper.Install(dst);
    serverApp.Start(Seconds(0));

    // =========================================================================
    // Seed-driven timing jitter for send events.
    // Packets still arrive in the same conceptual order; only timestamps shift.
    // =========================================================================
    Ptr<UniformRandomVariable> jitter = CreateObject<UniformRandomVariable>();
    jitter->SetAttribute("Min", DoubleValue(0.0));
    jitter->SetAttribute("Max", DoubleValue(0.2));

    Ipv4Address destAddr = ifR3Dst.GetAddress(1);
    double      baseTime = 1.0;
    double      step     = 2.0;

    // =========================================================================
    // Guidance for [C] questions: one socket per TTL value.
    // Socket::SetIpTtl() overrides the default OS TTL for that socket.
    // =========================================================================
    for (size_t i = 0; i < ttls.size(); ++i)
    {
        uint32_t ttlVal  = ttls[i];
        double   sendAt  = baseTime + i * step + jitter->GetValue();

        Ptr<Socket> sock = Socket::CreateSocket(src, UdpSocketFactory::GetTypeId());
        sock->SetIpTtl(ttlVal);

        Simulator::Schedule(Seconds(sendAt), [sock, destAddr, ttlVal]() {
            sock->Connect(InetSocketAddress(destAddr, DATA_PORT));
            Ptr<Packet> pkt = Create<Packet>(64);
            sock->Send(pkt);
            NS_LOG_INFO("Sent TTL=" << ttlVal << " packet");
        });
    }

    double simEnd = baseTime + ttls.size() * step + 6.0;
    serverApp.Stop(Seconds(simEnd));

    // =========================================================================
    // PCAP capture
    // Wireshark filters:
    //   "icmp.type==11"                 - Time Exceeded
    //   "icmp.type==11 && icmp.code==0" - TTL exceeded in transit
    // =========================================================================
    if (g_pcapEnabled)
    {
        p2p.EnablePcap(outputPath + "ttl-icmp-src", devSrcR1.Get(0), true);
        p2p.EnablePcap(outputPath + "ttl-icmp-r1",  devSrcR1.Get(1), true);
        p2p.EnablePcap(outputPath + "ttl-icmp-r2",  devR1R2.Get(1),  true);
        p2p.EnablePcap(outputPath + "ttl-icmp-r3",  devR2R3.Get(1),  true);
        p2p.EnablePcap(outputPath + "ttl-icmp-dst",  devR3Dst.Get(1), true);
    }

    std::stringstream topoInfo;
    topoInfo << "TTL-ICMP Scenario Topology\n";
    topoInfo << "=========================================\n\n";
    topoInfo << "Effective parameters:\n";
    topoInfo << "  seed    = " << cfg.seed    << "\n";
    topoInfo << "  ttlList = " << cfg.ttlList << "\n\n";
    topoInfo << "Linear Topology (4 hops SRC->DST):\n";
    topoInfo << "  [SRC]----[R1]----[R2]----[R3]----[DST]\n";
    topoInfo << "  10.1.1.1  .2|.1   .2|.1   .2|.1   .2\n\n";
    topoInfo << "IP Addresses:\n";
    topoInfo << "  SRC: 10.1.1.1\n";
    topoInfo << "  R1:  10.1.1.2 / 10.1.2.1\n";
    topoInfo << "  R2:  10.1.2.2 / 10.1.3.1\n";
    topoInfo << "  R3:  10.1.3.2 / 10.1.4.1\n";
    topoInfo << "  DST: 10.1.4.2\n\n";
    topoInfo << "TTL test packets:\n";
    for (size_t i = 0; i < ttls.size(); ++i)
    {
        uint32_t t = ttls[i];
        topoInfo << "  TTL=" << t << ": ";
        if      (t == 1) topoInfo << "expires at R1 (ICMP from 10.1.1.2)\n";
        else if (t == 2) topoInfo << "expires at R2 (ICMP from 10.1.2.2)\n";
        else if (t == 3) topoInfo << "expires at R3 (ICMP from 10.1.3.2)\n";
        else             topoInfo << "reaches DST\n";
    }
    topoInfo << "\nWireshark filters:\n";
    topoInfo << "  icmp.type==11                   - Time Exceeded\n";
    topoInfo << "  icmp.type==11 && icmp.code==0   - TTL exceeded in transit\n";
    topoInfo << "  icmp                            - All ICMP\n";
    WriteTopologyInfo(outputPath, topoInfo.str());

    Simulator::Stop(Seconds(simEnd));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("TTL-ICMP scenario complete.");
}

// =============================================================================
// MAIN FUNCTION
// =============================================================================

int
main(int argc, char* argv[])
{
    LabConfig cfg;

    // =========================================================================
    // Guidance for [C] questions: command-line argument parsing
    //
    // Original parameters (backward-compatible defaults):
    //   --scenario   lsdv | ospf-like | ttl-icmp
    //   --mode       ls | dv           (lsdv scenario only)
    //   --pcap       0 | 1
    //   --verbose    true | false
    //
    // New parameters (all have defaults matching original behaviour):
    //   --seed         RNG seed for reproducibility
    //   --r3r4Metric   cost of R3-R4 link (default 10 = original)
    //   --r2r4Metric   cost of R2-R4 link (default 1 = original)
    //   --lsaInterval  LSA flooding period in seconds (default 10 = original)
    //   --failureTime  R2-R4 failure time in seconds (default 40 = original)
    //   --pingInterval ICMP Echo Request interval in seconds (default 1 = original)
    //   --ttlList      comma-separated TTL values (default "1,2,3,4,64" = original)
    // =========================================================================

    CommandLine cmd(__FILE__);
    cmd.AddValue("scenario",     "Scenario: lsdv, ospf-like, ttl-icmp",         cfg.scenario);
    cmd.AddValue("mode",         "For lsdv: ls (Link State) or dv (Distance Vector)", cfg.mode);
    cmd.AddValue("pcap",         "Enable PCAP capture (0 or 1)",                 cfg.pcap);
    cmd.AddValue("verbose",      "Enable verbose logging",                        cfg.verbose);
    cmd.AddValue("seed",         "RNG seed (integer, default 100)",               cfg.seed);
    cmd.AddValue("r3r4Metric",   "Cost of R3-R4 link (positive integer)",         cfg.r3r4Metric);
    cmd.AddValue("r2r4Metric",   "Cost of R2-R4 link (positive integer)",         cfg.r2r4Metric);
    cmd.AddValue("lsaInterval",  "OSPF-like LSA interval in seconds (positive)",  cfg.lsaInterval);
    cmd.AddValue("failureTime",  "Time of R2-R4 link failure in seconds (positive)", cfg.failureTime);
    cmd.AddValue("pingInterval", "ICMP Echo Request interval in seconds (positive)", cfg.pingInterval);
    cmd.AddValue("ttlList",      "Comma-separated TTL values, e.g. 1,2,3,4,64",  cfg.ttlList);
    cmd.Parse(argc, argv);

    // =========================================================================
    // Input validation
    // =========================================================================
    if (cfg.scenario != "lsdv" && cfg.scenario != "ospf-like" && cfg.scenario != "ttl-icmp")
    {
        std::cerr << "ERROR: Invalid scenario '" << cfg.scenario << "'. "
                     "Valid: lsdv, ospf-like, ttl-icmp" << std::endl;
        return 1;
    }
    if (cfg.scenario == "lsdv" && cfg.mode != "ls" && cfg.mode != "dv")
    {
        std::cerr << "ERROR: Invalid mode '" << cfg.mode << "'. Valid: ls, dv" << std::endl;
        return 1;
    }
    if (cfg.r3r4Metric  <= 0) { std::cerr << "ERROR: r3r4Metric must be positive"  << std::endl; return 1; }
    if (cfg.r2r4Metric  <= 0) { std::cerr << "ERROR: r2r4Metric must be positive"  << std::endl; return 1; }
    // RIP (DV mode) uses infinity = 16.  The full path cost via R3 is
    // 1 (SRC->R1) + 1 (R1->R3) + r3r4Metric (R3->R4) + 1 (R4->DST) = 3 + r3r4Metric.
    // If 3 + r3r4Metric >= 16 (i.e. r3r4Metric >= 13) RIP considers that path
    // unreachable, so after the R2-R4 failure DV mode will NEVER converge.
    // LS (GlobalRouting) uses Dijkstra and has no such limit.
    if (cfg.scenario == "lsdv" && cfg.mode == "dv" && cfg.r3r4Metric >= 13)
    {
        std::cerr << "WARNING: r3r4Metric=" << cfg.r3r4Metric
                  << " >= 13 in DV mode: total path cost via R3 would be "
                  << (3 + cfg.r3r4Metric) << " >= RIP infinity (16).\n"
                  << "         The backup path will be UNREACHABLE — DV will not converge"
                     " after the R2-R4 link fails.\n"
                  << "         For DV experiments use r3r4Metric <= 12.\n";
    }
    if (cfg.lsaInterval <= 0) { std::cerr << "ERROR: lsaInterval must be positive" << std::endl; return 1; }
    if (cfg.failureTime <= 0) { std::cerr << "ERROR: failureTime must be positive"  << std::endl; return 1; }
    if (cfg.pingInterval<= 0) { std::cerr << "ERROR: pingInterval must be positive" << std::endl; return 1; }

    // =========================================================================
    // Set RNG seed for reproducibility.
    // Same seed -> identical output.  Different seed -> slightly different
    // packet timestamps (jitter) but same topology and routing decisions.
    // =========================================================================
    RngSeedManager::SetSeed(cfg.seed);

    g_pcapEnabled = (cfg.pcap == 1);

    if (cfg.verbose)
    {
        LogComponentEnable("RoutingLab", LOG_LEVEL_INFO);
        LogComponentEnable("Rip",        LOG_LEVEL_INFO);
        LogComponentEnable("Ping",       LOG_LEVEL_INFO);
    }

    std::cout << "=== ns-3 Routing Lab (Lab 4) ===" << std::endl;
    PrintEffectiveConfig(cfg);
    if (!g_pcapEnabled)
    {
        std::cout << "Note: Use --pcap=1 to enable PCAP capture for Wireshark" << std::endl;
    }

    EnsureDirectory(g_outputDir);

    bool success = true;

    // =========================================================================
    // Run selected scenario
    // =========================================================================
    if (cfg.scenario == "lsdv")
    {
        std::string outputPath = g_outputDir + "lsdv/";
        EnsureDirectory(outputPath);
        RunLsdvScenario(outputPath, (cfg.mode == "ls"), cfg);
        if (g_pcapEnabled)
            success = VerifyPcapFile(outputPath + "lsdv-src-r1-SRC-0.pcap") && success;
    }
    else if (cfg.scenario == "ospf-like")
    {
        std::string outputPath = g_outputDir + "ospf-like/";
        EnsureDirectory(outputPath);
        RunOspfLikeScenario(outputPath, cfg);
        if (g_pcapEnabled)
            success = VerifyPcapFile(outputPath + "ospf-like-r1r2-R1-0.pcap") && success;
    }
    else if (cfg.scenario == "ttl-icmp")
    {
        std::string outputPath = g_outputDir + "ttl-icmp/";
        EnsureDirectory(outputPath);
        RunTtlIcmpScenario(outputPath, cfg);
        if (g_pcapEnabled)
            success = VerifyPcapFile(outputPath + "ttl-icmp-src-SRC-TTL-0.pcap") && success;
    }

    std::cout << std::endl;
    std::cout << "=== Simulation Complete ===" << std::endl;
    std::cout << "Output: " << g_outputDir << std::endl;

    std::cout << std::endl;
    std::cout << "=== Wireshark Hints ===" << std::endl;
    if (cfg.scenario == "lsdv")
    {
        std::cout << "  rip             - RIP update messages (DV mode)" << std::endl;
        std::cout << "  icmp            - Ping traffic" << std::endl;
        std::cout << "  routing-tables.txt - convergence snapshots" << std::endl;
        if (cfg.r3r4Metric == cfg.r2r4Metric)
            std::cout << "  NOTE: equal-cost experiment - both paths may be used" << std::endl;
    }
    else if (cfg.scenario == "ospf-like")
    {
        std::cout << "  udp.port==" << LSA_PORT << "  - LSA packets" << std::endl;
        std::cout << "  LSA interval: " << cfg.lsaInterval << " s" << std::endl;
    }
    else if (cfg.scenario == "ttl-icmp")
    {
        std::cout << "  icmp.type==11   - Time Exceeded" << std::endl;
        std::cout << "  TTLs tested: " << cfg.ttlList << std::endl;
    }

    if (!g_pcapEnabled)
        std::cout << "WARNING: PCAP disabled. Add --pcap=1 for Wireshark files." << std::endl;
    else if (!success)
    {
        std::cerr << "ERROR: One or more PCAP files failed verification!" << std::endl;
        return 1;
    }

    return 0;
}
