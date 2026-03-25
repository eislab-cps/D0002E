/*
 * =============================================================================
 * ns-3 Wireshark Lab Simulation - TCP and UDP
 * Extended version with seed-based randomization, NetAnim support,
 * and parameterized experiments.
 * =============================================================================
 *
 * Changes vs lab2-with-guidance.cc:
 *   - --seed <1..100>      Reproducible runs; same seed = identical output
 *   - --linkDelay <value>  Override link delay for basic scenarios (default 2ms)
 *   - NetAnim XML produced per scenario with full packet metadata
 *   - MobilityHelper sets node positions so NetAnim renders the P2P layout
 *   - PacketMetadata::Enable() called once so every arrow carries header info
 *   - PCAP output placed under seed<N>/ subfolder to keep runs separate
 *
 * =============================================================================
 * HOW TO RUN EACH SCENARIO
 * =============================================================================
 *
 * Build:
 *   ./ns3 build scratch/d0002e/lab2-with-guidance
 *
 * Run scenarios (outputs go to "scratch/d0002e/lab 2 output/seed<N>/"):
 *
 * 1) TCP CONNECTION ESTABLISHMENT:
 *    ./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=tcp-handshake"
 *    ./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=tcp-handshake --seed=42"
 *
 * 2) TCP DATA TRANSFER AND SEGMENTATION:
 *    ./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=tcp-data"
 *    ./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=tcp-data --payloadSize=10000"
 *    ./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=tcp-data --payloadSize=100000"
 *
 * 3) TCP RELIABILITY AND RETRANSMISSION:
 *    ./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=tcp-loss"
 *    ./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=tcp-loss --lossRate=0.01"
 *    ./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=tcp-loss --lossRate=0.20"
 *
 * 4) TCP FLOW AND CONGESTION CONTROL:
 *    ./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=tcp-congestion"
 *    ./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=tcp-congestion --lossRate=0.01"
 *
 * 5) BASIC UDP TRANSMISSION:
 *    ./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=udp-basic"
 *    ./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=udp-basic --linkDelay=50ms"
 *
 * 6) UDP LOSS BEHAVIOR:
 *    ./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=udp-loss"
 *    ./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=udp-loss --lossRate=0.20"
 *
 * 7) ALL SCENARIOS:
 *    ./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=all"
 *    ./ns3 run "scratch/d0002e/lab2-with-guidance --scenario=all --seed=42 --verbose=true"
 *
 * Additional options:
 *   --verbose=true         Enable detailed logging
 *   --payloadSize=50000    TCP payload size for data/loss/congestion (default: 50000)
 *   --lossRate=0.05        Packet loss rate for loss/congestion scenarios (default: 0.05)
 *   --linkDelay=2ms        Link propagation delay for basic scenarios (default: 2ms)
 *   --serverPort=5001      Server port number (default: 5001)
 *   --seed=100             RNG seed 1-100 (default: 100)
 *
 * =============================================================================
 * NETWORK TOPOLOGY (all scenarios)
 * =============================================================================
 *
 *   +-------------+                    +-------------+
 *   |   Client    |                    |   Server    |
 *   |   (n0)      +--------------------+   (n1)      |
 *   |   10.1.1.1  |  Point-to-Point    |   10.1.1.2  |
 *   +-------------+                    +-------------+
 *
 *   Loss/Congestion variants add a RateErrorModel on the server's receive side.
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
#include "ns3/mobility-module.h"     // [NEW] ConstantPositionMobilityModel
#include "ns3/netanim-module.h"      // [NEW] AnimationInterface
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"

#include <filesystem>
#include <fstream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("TcpUdpLab");

// =============================================================================
// Output directory (note: contains space as per requirement)
// =============================================================================
static std::string g_outputDir = "scratch/d0002e/lab 2 output/";

// =============================================================================
// Relevant to [C]: g_payloadSize configures application data size for TCP
// Larger values force TCP to segment the data into multiple TCP segments
// =============================================================================
static uint32_t g_payloadSize = 50000;

// =============================================================================
// Relevant to [C]: g_lossRate configures the packet loss probability
// Used by RateErrorModel to induce packet loss for retransmission scenarios
// =============================================================================
static double g_lossRate = 0.05;

// =============================================================================
// Relevant to [C]: g_serverPort is the TCP/UDP server port number
// Relevant to [B]: This port number is visible in Wireshark as destination port
// =============================================================================
static uint16_t g_serverPort = 5001;

// =============================================================================
// [NEW] g_linkDelay: propagation delay for basic scenarios (tcp-handshake,
// tcp-data, udp-basic). Increasing it raises RTT and slows ACKs, making
// segmentation and window behavior more visible in Wireshark.
// Loss/congestion scenarios use their own hardcoded defaults (10 ms / 20 ms)
// which can be overridden by setting g_linkDelay on the command line.
// =============================================================================
static std::string g_linkDelay = "2ms";

// =============================================================================
// [NEW] Seed parameter for reproducible randomization (range 1-100, default 100)
// Same seed => identical run. Different seed => slightly different timing and
// initial sequence numbers, making runs distinguishable in PCAP/NetAnim.
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
// [NEW] SetupNetAnim: shared helper called inside each scenario after nodes
// and devices exist but before Simulator::Run().
//
// Installs ConstantPositionMobilityModel on n0/n1 so AnimationInterface reads
// real positions. Enables packet metadata so every animated arrow in NetAnim
// carries the full Ethernet/IP/TCP|UDP header description.
// =============================================================================
static void SetupNetAnim(AnimationInterface& anim,
                         NodeContainer& nodes,
                         double simStopTime)
{
    // -------------------------------------------------------------------------
    // [NEW] Packet metadata: anim.EnablePacketMetadata(true) writes a
    // meta-info attribute on each <p> element containing the full protocol
    // stack: EthernetHeader, Ipv4Header (src/dst, TTL, protocol),
    // TcpHeader or UdpHeader (ports, seq/ack), and payload size.
    // Requires PacketMetadata::Enable() called before topology setup (done in main).
    // -------------------------------------------------------------------------
    anim.EnablePacketMetadata(true);

    // -------------------------------------------------------------------------
    // [NEW] IPv4 packet counters: live overlay on each node in NetAnim showing
    // cumulative packets sent/received, polled every 0.5 s.
    // -------------------------------------------------------------------------
    anim.EnableIpv4L3ProtocolCounters(Seconds(0), Seconds(simStopTime), Seconds(0.5));

    // Node labels
    anim.UpdateNodeDescription(nodes.Get(0), "Client 10.1.1.1");
    anim.UpdateNodeDescription(nodes.Get(1), "Server 10.1.1.2");

    // Node colours
    anim.UpdateNodeColor(nodes.Get(0), 50, 130, 255);  // Blue  - client
    anim.UpdateNodeColor(nodes.Get(1), 0, 200, 80);    // Green - server

    // Node sizes
    anim.UpdateNodeSize(nodes.Get(0)->GetId(), 3.0, 3.0);
    anim.UpdateNodeSize(nodes.Get(1)->GetId(), 3.0, 3.0);
}

// =============================================================================
// [NEW] SetupMobility: installs ConstantPositionMobilityModel on the two nodes.
// AnimationInterface reads positions from the mobility model; without this the
// nodes appear stacked at (0,0) in NetAnim.
//
// Layout: Client left (10,50), Server right (90,50) - mirrors the P2P diagram.
// =============================================================================
static void SetupMobility(NodeContainer& nodes)
{
    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    Ptr<ListPositionAllocator> posAlloc = CreateObject<ListPositionAllocator>();
    posAlloc->Add(Vector(10.0, 50.0, 0.0));  // n0 Client
    posAlloc->Add(Vector(90.0, 50.0, 0.0));  // n1 Server
    mobility.SetPositionAllocator(posAlloc);
    mobility.Install(nodes);
}

// =============================================================================
// TCP HANDSHAKE SCENARIO
// =============================================================================
// Relevant to [V]: Demonstrates the TCP three-way handshake (Section 3.5.6)
//   - First segment: SYN flag set
//   - Second segment: SYN + ACK flags set
//   - Third segment: ACK flag set
//
// Relevant to [W]: Raw sequence numbers visible in Wireshark under
//   "Transmission Control Protocol" -> "Sequence number (raw)"
//
// Relevant to [B]: Server port (g_serverPort) is configured here and
//   visible in Wireshark as the TCP destination port in SYN segment
// =============================================================================

void RunTcpHandshakeScenario(const std::string& outputPath,
                              const std::string& animFile,
                              double jitter)
{
    NS_LOG_INFO("=== Running TCP Handshake Scenario ===");
    NS_LOG_INFO("This scenario demonstrates the TCP three-way handshake.");
    NS_LOG_INFO("Open " << outputPath << "client-0-0.pcap in Wireshark.");
    NS_LOG_INFO("Look for: SYN, SYN-ACK, ACK sequence (first 3 TCP segments).");

    NodeContainer nodes;
    nodes.Create(2);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    // [NEW] g_linkDelay is configurable; try --linkDelay=50ms to slow ACKs
    p2p.SetChannelAttribute("Delay", StringValue(g_linkDelay));

    NetDeviceContainer devices = p2p.Install(nodes);

    // [NEW] Fixed positions for NetAnim rendering
    SetupMobility(nodes);

    InternetStackHelper internet;
    internet.Install(nodes);

    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    // =============================================================================
    // Relevant to [C]: TCP Server Setup
    // PacketSink binds to g_serverPort and listens for incoming TCP connections.
    // The TCP stack automatically responds to SYN with SYN-ACK.
    // =============================================================================
    Address serverAddress(InetSocketAddress(interfaces.GetAddress(1), g_serverPort));
    PacketSinkHelper sinkHelper("ns3::TcpSocketFactory",
                                InetSocketAddress(Ipv4Address::GetAny(), g_serverPort));
    ApplicationContainer serverApp = sinkHelper.Install(nodes.Get(1));
    serverApp.Start(Seconds(0.0));
    serverApp.Stop(Seconds(10.0));

    // =============================================================================
    // Relevant to [C]: TCP Client Setup - Socket Creation and Connect()
    // OnOffApplication creates a TCP socket and calls Connect() which sends SYN.
    // [NEW] jitter (seed-derived, max 0.095 s) shifts start time for distinguishable runs.
    // =============================================================================
    OnOffHelper clientHelper("ns3::TcpSocketFactory", serverAddress);
    clientHelper.SetAttribute("DataRate", StringValue("1Mbps"));
    clientHelper.SetAttribute("PacketSize", UintegerValue(512));
    clientHelper.SetAttribute("MaxBytes", UintegerValue(512));

    ApplicationContainer clientApp = clientHelper.Install(nodes.Get(0));
    clientApp.Start(Seconds(1.0 + jitter));
    clientApp.Stop(Seconds(9.0));

    // =============================================================================
    // Relevant to [W]: Enable PCAP on client to capture the handshake
    //   1. SYN  (client -> server)
    //   2. SYN-ACK (server -> client)
    //   3. ACK  (client -> server)
    // Tip: Edit -> Preferences -> Protocols -> TCP -> uncheck Relative seq numbers
    // =============================================================================
    p2p.EnablePcap(outputPath + "client", devices.Get(0), true);
    p2p.EnablePcap(outputPath + "server", devices.Get(1), true);

    // [NEW] NetAnim output for this scenario
    AnimationInterface anim(animFile);
    SetupNetAnim(anim, nodes, 12.0);

    Simulator::Stop(Seconds(12.0));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("TCP Handshake scenario complete.");
    NS_LOG_INFO("Hint: In Wireshark, the first 3 TCP packets show the handshake.");
    NS_LOG_INFO("NetAnim file: " << animFile);
}

// =============================================================================
// TCP DATA TRANSFER SCENARIO
// =============================================================================
// Relevant to [W]: Multiple TCP segments carry the application data.
// Count segments with non-zero "TCP segment Len" in Wireshark.
//
// Relevant to [T]: TCP segments data because payload exceeds MSS (~1460 bytes).
//
// Relevant to [C]: The application does NOT explicitly segment data.
// TCP handles segmentation automatically when data exceeds MSS.
//
// [NEW] Experiment: vary --payloadSize to change the number of segments.
//   --payloadSize=1460   => 1 segment (fits in one MSS)
//   --payloadSize=10000  => ~7 segments
//   --payloadSize=50000  => ~35 segments (default)
//   --payloadSize=100000 => ~69 segments
// =============================================================================

void RunTcpDataScenario(const std::string& outputPath,
                         const std::string& animFile,
                         double jitter)
{
    NS_LOG_INFO("=== Running TCP Data Transfer Scenario ===");
    NS_LOG_INFO("This scenario demonstrates TCP segmentation of large data.");
    NS_LOG_INFO("Open " << outputPath << "client-0-0.pcap in Wireshark.");
    NS_LOG_INFO("Count TCP segments with non-zero 'TCP segment Len'.");

    NodeContainer nodes;
    nodes.Create(2);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue(g_linkDelay));

    NetDeviceContainer devices = p2p.Install(nodes);

    SetupMobility(nodes);

    InternetStackHelper internet;
    internet.Install(nodes);

    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    Address serverAddress(InetSocketAddress(interfaces.GetAddress(1), g_serverPort));
    PacketSinkHelper sinkHelper("ns3::TcpSocketFactory",
                                InetSocketAddress(Ipv4Address::GetAny(), g_serverPort));
    ApplicationContainer serverApp = sinkHelper.Install(nodes.Get(1));
    serverApp.Start(Seconds(0.0));
    serverApp.Stop(Seconds(30.0));

    // =============================================================================
    // Relevant to [C]: Payload Size Configuration
    // BulkSendApplication sends g_payloadSize bytes.
    // This exceeds TCP MSS (~1460 bytes), forcing TCP to segment automatically.
    //
    // [NEW] g_payloadSize is now a CLI parameter (--payloadSize=N).
    // Change it to observe how segment count scales with transfer size.
    // =============================================================================
    BulkSendHelper clientHelper("ns3::TcpSocketFactory", serverAddress);
    clientHelper.SetAttribute("MaxBytes", UintegerValue(g_payloadSize));
    clientHelper.SetAttribute("SendSize", UintegerValue(g_payloadSize));

    ApplicationContainer clientApp = clientHelper.Install(nodes.Get(0));
    clientApp.Start(Seconds(1.0 + jitter));
    clientApp.Stop(Seconds(29.0));

    p2p.EnablePcap(outputPath + "client", devices.Get(0), true);
    p2p.EnablePcap(outputPath + "server", devices.Get(1), true);

    AnimationInterface anim(animFile);
    SetupNetAnim(anim, nodes, 32.0);

    Simulator::Stop(Seconds(32.0));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("TCP Data Transfer scenario complete.");
    NS_LOG_INFO("Payload size: " << g_payloadSize << " bytes");
    NS_LOG_INFO("Expected segments: ~" << (g_payloadSize / 1460 + 1) << " (MSS ~1460 bytes)");
    NS_LOG_INFO("NetAnim file: " << animFile);
}

// =============================================================================
// TCP LOSS AND RETRANSMISSION SCENARIO
// =============================================================================
// Relevant to [W]: Retransmissions visible as "TCP Retransmission" in Wireshark.
//
// Relevant to [W]: Retransmission cause:
//   - Duplicate ACKs before retransmission -> fast retransmit
//   - Delay before retransmission without duplicates -> timeout (RTO)
//
// Relevant to [C]: TCP's reliability mechanism handles loss transparently.
// The application is unaware of loss, retransmission, or reordering.
//
// [NEW] Experiment: vary --lossRate to control retransmission frequency.
//   --lossRate=0.01  => rare retransmissions, mostly clean transfer
//   --lossRate=0.05  => moderate loss, several retransmissions (default)
//   --lossRate=0.15  => heavy loss, many retransmissions, slow completion
//   --lossRate=0.30  => severe loss, connection may stall
// =============================================================================

void RunTcpLossScenario(const std::string& outputPath,
                         const std::string& animFile,
                         double jitter)
{
    NS_LOG_INFO("=== Running TCP Loss/Retransmission Scenario ===");
    NS_LOG_INFO("This scenario induces packet loss to demonstrate TCP reliability.");
    NS_LOG_INFO("Open " << outputPath << "client-0-0.pcap in Wireshark.");
    NS_LOG_INFO("Look for 'TCP Retransmission' markers or duplicate sequence numbers.");

    NodeContainer nodes;
    nodes.Create(2);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    // Use g_linkDelay; default "2ms" keeps things fast, but "10ms" or "20ms"
    // makes retransmissions and timeout behavior easier to observe on the timeline.
    p2p.SetChannelAttribute("Delay", StringValue(g_linkDelay == "2ms" ? "10ms" : g_linkDelay));

    NetDeviceContainer devices = p2p.Install(nodes);

    // =============================================================================
    // Relevant to [C]: RateErrorModel Configuration
    // Randomly drops packets with probability g_lossRate.
    // Applied to the server's receive path to simulate channel loss.
    // TCP handles this transparently: detects loss and retransmits.
    //
    // [NEW] g_lossRate is configurable via --lossRate.
    // The same RNG stream is seeded by g_seed so results are reproducible.
    // =============================================================================
    Ptr<RateErrorModel> errorModel = CreateObject<RateErrorModel>();
    errorModel->SetAttribute("ErrorRate", DoubleValue(g_lossRate));
    errorModel->SetAttribute("ErrorUnit", EnumValue(RateErrorModel::ERROR_UNIT_PACKET));
    devices.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(errorModel));

    SetupMobility(nodes);

    InternetStackHelper internet;
    internet.Install(nodes);

    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    Address serverAddress(InetSocketAddress(interfaces.GetAddress(1), g_serverPort));
    PacketSinkHelper sinkHelper("ns3::TcpSocketFactory",
                                InetSocketAddress(Ipv4Address::GetAny(), g_serverPort));
    ApplicationContainer serverApp = sinkHelper.Install(nodes.Get(1));
    serverApp.Start(Seconds(0.0));
    serverApp.Stop(Seconds(60.0));

    // =============================================================================
    // Relevant to [C]: TCP Reliability - application sends without loss knowledge.
    // TCP detects loss via timeout or 3 duplicate ACKs and retransmits.
    // SendSize=1400 keeps each application write close to one MSS.
    // =============================================================================
    BulkSendHelper clientHelper("ns3::TcpSocketFactory", serverAddress);
    clientHelper.SetAttribute("MaxBytes", UintegerValue(100000));
    clientHelper.SetAttribute("SendSize", UintegerValue(1400));

    ApplicationContainer clientApp = clientHelper.Install(nodes.Get(0));
    clientApp.Start(Seconds(1.0 + jitter));
    clientApp.Stop(Seconds(59.0));

    // =============================================================================
    // Relevant to [W]: Analyzing Retransmissions in Wireshark
    // 1. Filter: "tcp.analysis.retransmission"
    // 2. Same seq number reappears -> retransmitted segment
    // 3. Duplicate ACKs before retransmission -> fast retransmit
    // 4. Long gap then retransmission -> RTO timeout
    // =============================================================================
    p2p.EnablePcap(outputPath + "client", devices.Get(0), true);
    p2p.EnablePcap(outputPath + "server", devices.Get(1), true);

    AnimationInterface anim(animFile);
    SetupNetAnim(anim, nodes, 62.0);

    Simulator::Stop(Seconds(62.0));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("TCP Loss/Retransmission scenario complete.");
    NS_LOG_INFO("Loss rate: " << (g_lossRate * 100) << "%");
    NS_LOG_INFO("Hint: Filter 'tcp.analysis.retransmission' in Wireshark.");
    NS_LOG_INFO("NetAnim file: " << animFile);
}

// =============================================================================
// TCP CONGESTION CONTROL SCENARIO
// =============================================================================
// Relevant to [W]: Time-Sequence Graph (Stevens) shows:
//   - Slow start: exponential cwnd growth (steep slope)
//   - Congestion avoidance: linear growth after ssthresh
//   - Loss event: rate drop, then recovery
//
// Relevant to [C]: TCP variant configured via Config::SetDefault() before
// any sockets are created. TcpNewReno implements:
//   - Slow start, congestion avoidance, fast retransmit, fast recovery
//
// [NEW] Experiment: vary --lossRate to change ssthresh and recovery behavior.
//   --lossRate=0.005 => rare events, long slow-start phase visible
//   --lossRate=0.02  => moderate (default in original, kept as internal default)
//   --lossRate=0.10  => frequent drops, cwnd never grows large
// Also try --linkDelay=50ms to make RTT visible between data bursts.
// =============================================================================

void RunTcpCongestionScenario(const std::string& outputPath,
                               const std::string& animFile,
                               double jitter)
{
    NS_LOG_INFO("=== Running TCP Congestion Control Scenario ===");
    NS_LOG_INFO("This scenario demonstrates TCP slow start and congestion avoidance.");
    NS_LOG_INFO("Open " << outputPath << "client-0-0.pcap in Wireshark.");
    NS_LOG_INFO("Use: Statistics -> TCP Stream Graphs -> Time-Sequence Graph (Stevens)");

    // =============================================================================
    // Relevant to [C]: TCP Variant Configuration
    // Config::SetDefault() sets the congestion control algorithm BEFORE sockets.
    // TcpNewReno: slow start, congestion avoidance, fast retransmit, fast recovery.
    // InitialCwnd=1 ensures slow start begins visibly from one segment.
    // =============================================================================
    Config::SetDefault("ns3::TcpL4Protocol::SocketType", StringValue("ns3::TcpNewReno"));
    Config::SetDefault("ns3::TcpSocket::InitialCwnd", UintegerValue(1));

    NodeContainer nodes;
    nodes.Create(2);

    // =============================================================================
    // Relevant to [T]: Link delay affects RTT.
    // RTT = 2 * propagation_delay. Larger RTT => slower cwnd growth.
    // The congestion scenario uses 20ms by default (40ms RTT) for clear graphs.
    // Override with --linkDelay=Xms to see how RTT scales slow-start duration.
    // =============================================================================
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue(g_linkDelay == "2ms" ? "20ms" : g_linkDelay));

    NetDeviceContainer devices = p2p.Install(nodes);

    // =============================================================================
    // [NEW] g_lossRate replaces the hardcoded 0.02 loss in the original.
    // Default is still 0.05 (from CLI), but --lossRate=0.02 matches original.
    // Lower values show longer slow-start; higher values show frequent drops.
    // =============================================================================
    Ptr<RateErrorModel> errorModel = CreateObject<RateErrorModel>();
    errorModel->SetAttribute("ErrorRate", DoubleValue(g_lossRate));
    errorModel->SetAttribute("ErrorUnit", EnumValue(RateErrorModel::ERROR_UNIT_PACKET));
    devices.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(errorModel));

    SetupMobility(nodes);

    InternetStackHelper internet;
    internet.Install(nodes);

    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    Address serverAddress(InetSocketAddress(interfaces.GetAddress(1), g_serverPort));
    PacketSinkHelper sinkHelper("ns3::TcpSocketFactory",
                                InetSocketAddress(Ipv4Address::GetAny(), g_serverPort));
    ApplicationContainer serverApp = sinkHelper.Install(nodes.Get(1));
    serverApp.Start(Seconds(0.0));
    serverApp.Stop(Seconds(120.0));

    // =============================================================================
    // Relevant to [B]: 500 KB transfer to observe full congestion window evolution.
    // Time-sequence graph shows: exponential growth -> ssthresh -> linear growth
    // -> loss event -> cwnd halved -> recovery.
    // =============================================================================
    BulkSendHelper clientHelper("ns3::TcpSocketFactory", serverAddress);
    clientHelper.SetAttribute("MaxBytes", UintegerValue(500000));
    clientHelper.SetAttribute("SendSize", UintegerValue(1400));

    ApplicationContainer clientApp = clientHelper.Install(nodes.Get(0));
    clientApp.Start(Seconds(1.0 + jitter));
    clientApp.Stop(Seconds(119.0));

    p2p.EnablePcap(outputPath + "client", devices.Get(0), true);
    p2p.EnablePcap(outputPath + "server", devices.Get(1), true);

    AnimationInterface anim(animFile);
    SetupNetAnim(anim, nodes, 122.0);

    Simulator::Stop(Seconds(122.0));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("TCP Congestion Control scenario complete.");
    NS_LOG_INFO("TCP Variant: TcpNewReno, loss rate: " << (g_lossRate * 100) << "%");
    NS_LOG_INFO("Hint: Statistics -> TCP Stream Graphs -> Time-Sequence Graph (Stevens)");
    NS_LOG_INFO("NetAnim file: " << animFile);
}

// =============================================================================
// UDP BASIC SCENARIO
// =============================================================================
// Relevant to [V]: UDP header has exactly 4 fields (Section 3.3.1):
//   1. Source Port (16 bits)
//   2. Destination Port (16 bits)
//   3. Length (16 bits)
//   4. Checksum (16 bits)
//
// Relevant to [W]: IP header shows Protocol = 17 for UDP.
//
// Relevant to [C]: UDP is connectionless - no handshake, no ACKs, no cwnd.
//
// [NEW] Experiment: vary --linkDelay to see how latency appears in PCAP timestamps.
//   --linkDelay=2ms   => datagrams arrive in ~4ms
//   --linkDelay=50ms  => datagrams arrive in ~100ms; RTT visible in Wireshark time col
// =============================================================================

void RunUdpBasicScenario(const std::string& outputPath,
                          const std::string& animFile,
                          double jitter)
{
    NS_LOG_INFO("=== Running Basic UDP Scenario ===");
    NS_LOG_INFO("This scenario demonstrates UDP's connectionless transmission.");
    NS_LOG_INFO("Open " << outputPath << "client-0-0.pcap in Wireshark.");
    NS_LOG_INFO("Note: No handshake - data transmission starts immediately.");
    NS_LOG_INFO("Inspect UDP header: 4 fields (Src Port, Dst Port, Length, Checksum).");

    NodeContainer nodes;
    nodes.Create(2);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue(g_linkDelay));

    NetDeviceContainer devices = p2p.Install(nodes);

    SetupMobility(nodes);

    InternetStackHelper internet;
    internet.Install(nodes);

    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    // =============================================================================
    // Relevant to [C]: UDP Server - no Listen(), just Bind() to g_serverPort.
    // UDP is connectionless; the socket receives any datagram sent to that port.
    // =============================================================================
    Address serverAddress(InetSocketAddress(interfaces.GetAddress(1), g_serverPort));
    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory",
                                InetSocketAddress(Ipv4Address::GetAny(), g_serverPort));
    ApplicationContainer serverApp = sinkHelper.Install(nodes.Get(1));
    serverApp.Start(Seconds(0.0));
    serverApp.Stop(Seconds(30.0));

    // =============================================================================
    // Relevant to [C]: UDP Client - no Connect(), no handshake.
    // Data is sent immediately via SendTo(). No waiting for acknowledgements.
    //
    // Relevant to [B]: Destination port (g_serverPort) visible in Wireshark
    // as UDP destination port field. Source port is ephemeral (assigned by OS).
    // =============================================================================
    OnOffHelper clientHelper("ns3::UdpSocketFactory", serverAddress);
    clientHelper.SetAttribute("DataRate", StringValue("1Mbps"));
    clientHelper.SetAttribute("PacketSize", UintegerValue(1024));
    clientHelper.SetAttribute("MaxBytes", UintegerValue(10240));

    ApplicationContainer clientApp = clientHelper.Install(nodes.Get(0));
    clientApp.Start(Seconds(1.0 + jitter));
    clientApp.Stop(Seconds(29.0));

    // =============================================================================
    // Relevant to [W]: Analyzing UDP in Wireshark
    // 1. Filter: "udp"
    // 2. IP header: Protocol = 17 (decimal) = 0x11
    // 3. UDP header: 4 fields, each 2 bytes (total 8 bytes)
    // 4. No SYN/ACK/FIN - data starts immediately, stops without FIN
    // =============================================================================
    p2p.EnablePcap(outputPath + "client", devices.Get(0), true);
    p2p.EnablePcap(outputPath + "server", devices.Get(1), true);

    AnimationInterface anim(animFile);
    SetupNetAnim(anim, nodes, 32.0);

    Simulator::Stop(Seconds(32.0));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("Basic UDP scenario complete.");
    NS_LOG_INFO("UDP destination port: " << g_serverPort);
    NS_LOG_INFO("Hint: Filter 'udp' in Wireshark to see UDP packets.");
    NS_LOG_INFO("NetAnim file: " << animFile);
}

// =============================================================================
// UDP LOSS SCENARIO
// =============================================================================
// Relevant to [W]: Lost UDP packets are NOT retransmitted.
// Compare packet count at client vs server - counts will differ.
//
// Relevant to [B]: TCP vs UDP under identical loss:
//   - TCP: retransmits, reduces rate, guarantees delivery
//   - UDP: no retransmission, steady rate, packets lost permanently
//
// [NEW] Experiment: vary --lossRate to see UDP vs TCP diverge under different loss.
//   --lossRate=0.01 => 1% loss, small discrepancy
//   --lossRate=0.10 => 10% loss, clearly visible gap
//   --lossRate=0.30 => 30% loss, dramatic delivery failure for UDP
// Run tcp-loss with the SAME --lossRate to compare side-by-side.
// =============================================================================

void RunUdpLossScenario(const std::string& outputPath,
                         const std::string& animFile,
                         double jitter)
{
    NS_LOG_INFO("=== Running UDP Loss Scenario ===");
    NS_LOG_INFO("This scenario demonstrates UDP's lack of reliability.");
    NS_LOG_INFO("Open " << outputPath << "client-0-0.pcap in Wireshark.");
    NS_LOG_INFO("Compare packets sent vs received - lost packets are NOT retransmitted.");

    NodeContainer nodes;
    nodes.Create(2);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue(g_linkDelay == "2ms" ? "10ms" : g_linkDelay));

    NetDeviceContainer devices = p2p.Install(nodes);

    // =============================================================================
    // Relevant to [C]: Same RateErrorModel as TCP loss scenario.
    // The key difference: UDP does not detect or recover from this loss.
    // No retransmission, no rate reduction, no acknowledgement mechanism.
    // =============================================================================
    Ptr<RateErrorModel> errorModel = CreateObject<RateErrorModel>();
    errorModel->SetAttribute("ErrorRate", DoubleValue(g_lossRate));
    errorModel->SetAttribute("ErrorUnit", EnumValue(RateErrorModel::ERROR_UNIT_PACKET));
    devices.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(errorModel));

    SetupMobility(nodes);

    InternetStackHelper internet;
    internet.Install(nodes);

    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    Address serverAddress(InetSocketAddress(interfaces.GetAddress(1), g_serverPort));
    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory",
                                InetSocketAddress(Ipv4Address::GetAny(), g_serverPort));
    ApplicationContainer serverApp = sinkHelper.Install(nodes.Get(1));
    serverApp.Start(Seconds(0.0));
    serverApp.Stop(Seconds(60.0));

    // =============================================================================
    // Relevant to [C]: UDP sender does NOT adapt rate after loss.
    // No feedback exists. The sender transmits at constant 2 Mbps regardless.
    // Compare with TCP loss scenario: TCP will slow down after detecting loss.
    // =============================================================================
    OnOffHelper clientHelper("ns3::UdpSocketFactory", serverAddress);
    clientHelper.SetAttribute("DataRate", StringValue("2Mbps"));
    clientHelper.SetAttribute("PacketSize", UintegerValue(1024));
    clientHelper.SetAttribute("MaxBytes", UintegerValue(102400));

    ApplicationContainer clientApp = clientHelper.Install(nodes.Get(0));
    clientApp.Start(Seconds(1.0 + jitter));
    clientApp.Stop(Seconds(59.0));

    // =============================================================================
    // Relevant to [W]: Analyzing UDP Loss in Wireshark
    // 1. Filter "udp" and count frames in client pcap (sent) vs server pcap (received)
    // 2. No "Retransmission" markers - UDP has no such concept
    // 3. Compare with tcp-loss pcap: TCP shows retransmissions, UDP doesn't
    // =============================================================================
    p2p.EnablePcap(outputPath + "client", devices.Get(0), true);
    p2p.EnablePcap(outputPath + "server", devices.Get(1), true);

    AnimationInterface anim(animFile);
    SetupNetAnim(anim, nodes, 62.0);

    Simulator::Stop(Seconds(62.0));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("UDP Loss scenario complete.");
    NS_LOG_INFO("Loss rate: " << (g_lossRate * 100) << "%");
    NS_LOG_INFO("Hint: Compare UDP packet count in client vs server pcap files.");
    NS_LOG_INFO("NetAnim file: " << animFile);
}

// =============================================================================
// MAIN FUNCTION
// =============================================================================

int main(int argc, char* argv[])
{
    std::string scenario = "all";
    bool verbose = false;

    CommandLine cmd(__FILE__);
    cmd.AddValue("scenario", "Scenario: tcp-handshake, tcp-data, tcp-loss, tcp-congestion, "
                             "udp-basic, udp-loss, all", scenario);
    cmd.AddValue("verbose",     "Enable verbose logging", verbose);
    cmd.AddValue("payloadSize", "TCP payload size for data transfer (bytes)", g_payloadSize);
    cmd.AddValue("lossRate",    "Packet loss rate 0.0-1.0", g_lossRate);
    cmd.AddValue("serverPort",  "Server port number", g_serverPort);
    // [NEW] link delay and seed
    cmd.AddValue("linkDelay",   "Link propagation delay for basic scenarios (e.g. 2ms, 10ms, 50ms)", g_linkDelay);
    cmd.AddValue("seed",        "RNG seed 1-100 (default 100)", g_seed);
    cmd.Parse(argc, argv);

    // =============================================================================
    // [NEW] Seed-based reproducibility.
    // RngSeedManager makes every random draw (error model, OnOff inter-packet
    // gaps) deterministic for the given seed.
    // seedJitter: small timing offset (0..0.095 s) shifts PCAP timestamps so
    // runs with different seeds are distinguishable without breaking behavior.
    // =============================================================================
    if (g_seed < 1)   g_seed = 1;
    if (g_seed > 100) g_seed = 100;
    RngSeedManager::SetSeed(g_seed);
    RngSeedManager::SetRun(g_seed);
    double seedJitter = (g_seed % 20) * 0.005;  // 0.000 .. 0.095 s

    // =============================================================================
    // [NEW] PacketMetadata::Enable() must be called before any packets are
    // created (i.e. before topology setup inside any scenario function).
    // It enables ns-3 to record full header descriptions on every packet so
    // AnimationInterface::EnablePacketMetadata(true) has data to write.
    // =============================================================================
    PacketMetadata::Enable();

    if (verbose)
    {
        LogComponentEnable("TcpUdpLab", LOG_LEVEL_INFO);
        LogComponentEnable("BulkSendApplication", LOG_LEVEL_INFO);
        LogComponentEnable("PacketSink", LOG_LEVEL_INFO);
        LogComponentEnable("OnOffApplication", LOG_LEVEL_INFO);
    }

    // Validate scenario
    std::vector<std::string> validScenarios = {
        "tcp-handshake", "tcp-data", "tcp-loss", "tcp-congestion",
        "udp-basic", "udp-loss", "all"
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
    // coexist without overwriting each other.
    // =============================================================================
    std::string seedDir = g_outputDir + "seed" + std::to_string(g_seed) + "/";

    std::cout << "=== ns-3 TCP/UDP Lab ===" << std::endl;
    std::cout << "Scenario:   " << scenario    << std::endl;
    std::cout << "Seed:       " << g_seed      << "  (jitter=" << seedJitter << "s)" << std::endl;
    std::cout << "PayloadSize:" << g_payloadSize << " bytes" << std::endl;
    std::cout << "LossRate:   " << (g_lossRate * 100) << "%" << std::endl;
    std::cout << "LinkDelay:  " << g_linkDelay  << std::endl;

    std::error_code ec;
    std::filesystem::create_directories(seedDir, ec);
    if (ec)
    {
        std::cerr << "Failed to create output directory: " << seedDir << std::endl;
        return 1;
    }

    bool success = true;

    // Helper lambda: returns the output path and creates the directory
    auto makeOutputPath = [&](const std::string& sub) -> std::string {
        std::string path = (scenario == "all") ? seedDir + sub + "/" : seedDir;
        std::filesystem::create_directories(path, ec);
        return path;
    };

    // Helper lambda: returns the NetAnim XML path for a scenario
    auto makeAnimFile = [&](const std::string& sub) -> std::string {
        return makeOutputPath(sub) + "netanim.xml";
    };

    if (scenario == "tcp-handshake" || scenario == "all")
    {
        std::string path = makeOutputPath("tcp-handshake");
        std::string anim = makeAnimFile("tcp-handshake");
        RunTcpHandshakeScenario(path, anim, seedJitter);
        success = success && VerifyPcapFile(path + "client-0-0.pcap");
    }

    if (scenario == "tcp-data" || scenario == "all")
    {
        std::string path = makeOutputPath("tcp-data");
        std::string anim = makeAnimFile("tcp-data");
        RunTcpDataScenario(path, anim, seedJitter);
        success = success && VerifyPcapFile(path + "client-0-0.pcap");
    }

    if (scenario == "tcp-loss" || scenario == "all")
    {
        std::string path = makeOutputPath("tcp-loss");
        std::string anim = makeAnimFile("tcp-loss");
        RunTcpLossScenario(path, anim, seedJitter);
        success = success && VerifyPcapFile(path + "client-0-0.pcap");
    }

    if (scenario == "tcp-congestion" || scenario == "all")
    {
        std::string path = makeOutputPath("tcp-congestion");
        std::string anim = makeAnimFile("tcp-congestion");
        RunTcpCongestionScenario(path, anim, seedJitter);
        success = success && VerifyPcapFile(path + "client-0-0.pcap");
    }

    if (scenario == "udp-basic" || scenario == "all")
    {
        std::string path = makeOutputPath("udp-basic");
        std::string anim = makeAnimFile("udp-basic");
        RunUdpBasicScenario(path, anim, seedJitter);
        success = success && VerifyPcapFile(path + "client-0-0.pcap");
    }

    if (scenario == "udp-loss" || scenario == "all")
    {
        std::string path = makeOutputPath("udp-loss");
        std::string anim = makeAnimFile("udp-loss");
        RunUdpLossScenario(path, anim, seedJitter);
        success = success && VerifyPcapFile(path + "client-0-0.pcap");
    }

    std::cout << std::endl;
    std::cout << "=== Simulation Complete ===" << std::endl;
    std::cout << "Output directory: " << seedDir << std::endl;
    std::cout << std::endl;
    std::cout << "=== Analysis Hints ===" << std::endl;
    std::cout << "- TCP Handshake:   Look for SYN, SYN-ACK, ACK flags" << std::endl;
    std::cout << "- TCP Data:        Count segments with non-zero 'TCP segment Len'" << std::endl;
    std::cout << "- TCP Loss:        Filter 'tcp.analysis.retransmission'" << std::endl;
    std::cout << "- TCP Congestion:  Statistics -> TCP Stream Graphs -> Time-Sequence Graph (Stevens)" << std::endl;
    std::cout << "- UDP Basic:       Inspect 4-field UDP header, IP Protocol=17" << std::endl;
    std::cout << "- UDP Loss:        Compare packet counts (no retransmissions)" << std::endl;
    std::cout << "- NetAnim:         Open netanim.xml in each subfolder with NetAnim viewer" << std::endl;

    if (!success)
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
 * All commands below assume --scenario=<name>. Use --seed=N to keep runs
 * reproducible and distinguishable. Output goes to lab 2 output/seed<N>/.
 *
 * -----------------------------------------------------------------------------
 * 1. TCP DATA TRANSFER AND SEGMENTATION  (vary --payloadSize)
 * -----------------------------------------------------------------------------
 * Question: How many TCP segments carry the data? Why?
 *
 *   payloadSize=1460   ~1 data segment  (fits in one MSS, no segmentation)
 *   payloadSize=10000  ~7 segments
 *   payloadSize=50000  ~35 segments     (default)
 *   payloadSize=100000 ~69 segments
 *
 * Commands:
 *   ./ns3 run "... --scenario=tcp-data --payloadSize=1460  --seed=42"
 *   ./ns3 run "... --scenario=tcp-data --payloadSize=10000 --seed=42"
 *   ./ns3 run "... --scenario=tcp-data --payloadSize=50000 --seed=42"
 *
 * Observe in Wireshark:
 *   - Segment count scales with payloadSize / 1460 (rounded up)
 *   - Sequence numbers advance by MSS per segment
 *   - Advertised receiver window visible in first ACK
 *
 * -----------------------------------------------------------------------------
 * 2. TCP RELIABILITY AND RETRANSMISSION  (vary --lossRate)
 * -----------------------------------------------------------------------------
 * Question: Are segments retransmitted? What triggers retransmission?
 *
 *   lossRate=0.01  =>  ~1 retransmission per 100 packets (rare, clean)
 *   lossRate=0.05  =>  several retransmissions (default)
 *   lossRate=0.15  =>  frequent retransmissions, long transfer time
 *   lossRate=0.30  =>  severe; connection may timeout
 *
 * Commands:
 *   ./ns3 run "... --scenario=tcp-loss --lossRate=0.01 --seed=42"
 *   ./ns3 run "... --scenario=tcp-loss --lossRate=0.10 --seed=42"
 *   ./ns3 run "... --scenario=tcp-loss --lossRate=0.20 --seed=42"
 *
 * Observe in Wireshark (filter: tcp.analysis.retransmission):
 *   - Retransmission count grows with lossRate
 *   - Three duplicate ACKs before retransmission -> fast retransmit
 *   - Long pause then retransmission -> RTO timeout
 *   - Sequence number of first retransmission visible in PCAP
 *
 * -----------------------------------------------------------------------------
 * 3. TCP FLOW AND CONGESTION CONTROL  (vary --lossRate, optionally --linkDelay)
 * -----------------------------------------------------------------------------
 * Question: When does congestion avoidance begin? How does loss affect cwnd?
 *
 *   lossRate=0.005 => rare drops; long slow-start, wide cwnd swings
 *   lossRate=0.02  => matches original hardcoded value
 *   lossRate=0.05  => default; frequent drops, cwnd rarely grows large
 *   lossRate=0.10  => heavy loss; cwnd stays small, throughput low
 *
 *   linkDelay=5ms  => short RTT, cwnd grows fast (steep slope in graph)
 *   linkDelay=20ms => default for congestion; RTT clearly visible
 *   linkDelay=50ms => slow cwnd growth; each RTT takes 100ms
 *
 * Commands:
 *   ./ns3 run "... --scenario=tcp-congestion --lossRate=0.005 --seed=42"
 *   ./ns3 run "... --scenario=tcp-congestion --lossRate=0.02  --seed=42"
 *   ./ns3 run "... --scenario=tcp-congestion --linkDelay=50ms --seed=42"
 *
 * Observe in Wireshark (Statistics -> TCP Stream Graphs -> Time-Sequence Stevens):
 *   - Initial steep slope = slow start (exponential cwnd growth)
 *   - Slope flattens at ssthresh = start of congestion avoidance
 *   - Sudden drop in slope = loss event, cwnd halved (NewReno)
 *   - Lower lossRate => cwnd grows larger before first event
 *
 * -----------------------------------------------------------------------------
 * 4. UDP LOSS BEHAVIOR  (vary --lossRate, then compare with tcp-loss)
 * -----------------------------------------------------------------------------
 * Question: Are lost UDP packets retransmitted? Compare with TCP under same loss.
 *
 * Run both with the same --lossRate and --seed to make a fair comparison:
 *   ./ns3 run "... --scenario=tcp-loss  --lossRate=0.10 --seed=42"
 *   ./ns3 run "... --scenario=udp-loss  --lossRate=0.10 --seed=42"
 *
 * Observe in Wireshark:
 *   TCP client pcap: retransmissions appear (same seq number reused)
 *   UDP client pcap: no retransmissions, steady packet stream
 *   UDP server pcap: fewer packets than client (gaps, no recovery)
 *   TCP server pcap: all bytes eventually delivered (complete transfer)
 *
 * -----------------------------------------------------------------------------
 * 5. LINK DELAY / RTT  (vary --linkDelay for conceptual comparison)
 * -----------------------------------------------------------------------------
 * Vary linkDelay across scenarios to see its effect on timing:
 *   --linkDelay=2ms   => fast link, tight timestamps in PCAP
 *   --linkDelay=10ms  => clearly visible RTT (20ms round-trip)
 *   --linkDelay=50ms  => 100ms RTT; handshake takes 300ms, obvious in Wireshark
 *
 * Commands:
 *   ./ns3 run "... --scenario=tcp-handshake --linkDelay=2ms  --seed=42"
 *   ./ns3 run "... --scenario=tcp-handshake --linkDelay=50ms --seed=42"
 *
 * Observe in Wireshark (time column):
 *   - Time between SYN and SYN-ACK = one-way propagation delay
 *   - Time between SYN-ACK and ACK = client processing + one-way delay
 * =============================================================================
 */
