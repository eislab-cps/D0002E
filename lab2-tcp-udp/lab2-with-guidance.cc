/*
 * =============================================================================
 * ns-3 Wireshark Lab Simulation - TCP and UDP
 * =============================================================================
 *
 * This script generates PCAP files for Wireshark TCP and UDP lab exercises.
 * Based on Kurose & Ross "Computer Networking: A Top-Down Approach" labs v8.0.
 *
 * =============================================================================
 * HOW TO RUN EACH SCENARIO
 * =============================================================================
 *
 * Build:
 *   ./ns3 build
 *   (or specifically: ./ns3 build scratch_d0002e_lab2-with-guidance)
 *
 * Run scenarios (outputs go to "scratch/d0002e/lab 2 output/"):
 *
 * 1) TCP CONNECTION ESTABLISHMENT (TCP Handshake):
 *    ./ns3 run "scratch/d0002e/lab2 --scenario=tcp-handshake"
 *    PCAP: client-0-0.pcap - Shows SYN, SYN-ACK, ACK three-way handshake
 *    Wireshark: Inspect raw sequence numbers in TCP header details
 *
 * 2) TCP DATA TRANSFER AND SEGMENTATION:
 *    ./ns3 run "scratch/d0002e/lab2 --scenario=tcp-data"
 *    PCAP: client-0-0.pcap - Shows multiple TCP segments with application data
 *    Wireshark: Count segments with non-zero "TCP segment Len"
 *
 * 3) TCP RELIABILITY AND RETRANSMISSION:
 *    ./ns3 run "scratch/d0002e/lab2 --scenario=tcp-loss"
 *    PCAP: client-0-0.pcap - Shows TCP retransmissions due to induced loss
 *    Wireshark: Look for "TCP Retransmission" markers
 *
 * 4) TCP FLOW AND CONGESTION CONTROL:
 *    ./ns3 run "scratch/d0002e/lab2 --scenario=tcp-congestion"
 *    PCAP: client-0-0.pcap - Shows slow start and congestion avoidance
 *    Wireshark: Statistics -> TCP Stream Graphs -> Time-Sequence Graph (Stevens)
 *
 * 5) BASIC UDP TRANSMISSION:
 *    ./ns3 run "scratch/d0002e/lab2 --scenario=udp-basic"
 *    PCAP: client-0-0.pcap - Shows UDP datagrams (no handshake)
 *    Wireshark: Inspect UDP header fields (4 fields total)
 *
 * 6) UDP LOSS BEHAVIOR:
 *    ./ns3 run "scratch/d0002e/lab2 --scenario=udp-loss"
 *    PCAP: client-0-0.pcap - Shows UDP packets with induced loss (no retransmissions)
 *    Wireshark: Compare packet count sent vs received
 *
 * 7) ALL SCENARIOS:
 *    ./ns3 run "scratch/d0002e/lab2 --scenario=all"
 *    PCAP: Separate subfolder per scenario, each with client-0-0.pcap
 *
 * Additional options:
 *   --verbose=true      Enable detailed logging
 *   --payloadSize=50000 TCP payload size for data transfer (default: 50000)
 *   --lossRate=0.05     Packet loss rate for loss scenarios (default: 0.05)
 *
 * =============================================================================
 * NETWORK TOPOLOGY
 * =============================================================================
 *
 * Basic scenarios (tcp-handshake, tcp-data, udp-basic):
 *
 *   +-------------+                    +-------------+
 *   |   Client    |                    |   Server    |
 *   |   (n0)      +--------------------+   (n1)      |
 *   |   10.1.1.1  |    Point-to-Point  |   10.1.1.2  |
 *   +-------------+      100 Mbps      +-------------+
 *                        2ms delay
 *
 * Loss/Congestion scenarios (tcp-loss, tcp-congestion, udp-loss):
 *
 *   +-------------+                    +-------------+
 *   |   Client    |                    |   Server    |
 *   |   (n0)      +--------------------+   (n1)      |
 *   |   10.1.1.1  |    P2P + Error     |   10.1.1.2  |
 *   +-------------+      Model         +-------------+
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
// Note: Using port 5001 (commonly used for testing) to avoid Wireshark
// interpreting traffic as a specific protocol (e.g., port 9 = DISCARD)
// =============================================================================
static uint16_t g_serverPort = 5001;

// =============================================================================
// PCAP VERIFICATION HELPER
// =============================================================================
// Verifies PCAP files exist and have non-zero size
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
// Relevant to [B]: Server port (g_serverPort = 9) is configured here and
//   visible in Wireshark as the TCP destination port in SYN segment
// =============================================================================

void RunTcpHandshakeScenario(const std::string& outputPath)
{
    NS_LOG_INFO("=== Running TCP Handshake Scenario ===");
    NS_LOG_INFO("This scenario demonstrates the TCP three-way handshake.");
    NS_LOG_INFO("Open " << outputPath << "client-0-0.pcap in Wireshark.");
    NS_LOG_INFO("Look for: SYN, SYN-ACK, ACK sequence (first 3 TCP segments).");

    // Create nodes
    NodeContainer nodes;
    nodes.Create(2);

    // Create point-to-point link
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("2ms"));

    NetDeviceContainer devices = p2p.Install(nodes);

    // Install Internet stack
    InternetStackHelper internet;
    internet.Install(nodes);

    // Assign IP addresses
    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    // =============================================================================
    // Relevant to [C]: TCP Server Setup
    // The server uses PacketSink to accept incoming TCP connections.
    // Bind() binds to port g_serverPort, Listen() puts socket in listening state.
    // When a SYN arrives, TCP stack automatically responds with SYN-ACK.
    // =============================================================================

    // Create TCP server using PacketSink (receives data)
    Address serverAddress(InetSocketAddress(interfaces.GetAddress(1), g_serverPort));
    PacketSinkHelper sinkHelper("ns3::TcpSocketFactory",
                                 InetSocketAddress(Ipv4Address::GetAny(), g_serverPort));
    ApplicationContainer serverApp = sinkHelper.Install(nodes.Get(1));
    serverApp.Start(Seconds(0.0));
    serverApp.Stop(Seconds(10.0));

    // =============================================================================
    // Relevant to [C]: TCP Client Setup - Socket Creation and Connect()
    // OnOffApplication creates a TCP socket using Socket::CreateSocket()
    // and calls Connect() to the server's IP address and port.
    // The Connect() call triggers the SYN segment to be sent.
    // =============================================================================

    // Create TCP client using OnOffApplication (sends minimal data)
    OnOffHelper clientHelper("ns3::TcpSocketFactory", serverAddress);
    // Relevant to [C]: Small data amount to focus on handshake
    clientHelper.SetAttribute("DataRate", StringValue("1Mbps"));
    clientHelper.SetAttribute("PacketSize", UintegerValue(512));
    clientHelper.SetAttribute("MaxBytes", UintegerValue(512)); // Send minimal data

    ApplicationContainer clientApp = clientHelper.Install(nodes.Get(0));
    clientApp.Start(Seconds(1.0));
    clientApp.Stop(Seconds(9.0));

    // =============================================================================
    // Relevant to [W]: Enable PCAP on client to capture the handshake
    // The client-0-0.pcap file will show:
    //   1. SYN (client -> server): Client initiates connection
    //   2. SYN-ACK (server -> client): Server acknowledges and synchronizes
    //   3. ACK (client -> server): Client completes handshake
    // To see raw sequence numbers: Wireshark -> Edit -> Preferences ->
    //   Protocols -> TCP -> Uncheck "Relative sequence numbers"
    // =============================================================================

    p2p.EnablePcap(outputPath + "client", devices.Get(0), true);
    p2p.EnablePcap(outputPath + "server", devices.Get(1), true);

    Simulator::Stop(Seconds(12.0));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("TCP Handshake scenario complete.");
    NS_LOG_INFO("Hint: In Wireshark, the first 3 TCP packets show the handshake.");
}

// =============================================================================
// TCP DATA TRANSFER SCENARIO
// =============================================================================
// Relevant to [W]: Multiple TCP segments carry the application data
// Count segments with non-zero "TCP segment Len" in Wireshark
//
// Relevant to [T]: TCP segments data because payload exceeds MSS (Section 3.5.2)
// The MSS is typically ~1460 bytes for Ethernet (1500 MTU - 40 byte headers)
//
// Relevant to [C]: The application does NOT explicitly segment data.
// TCP handles segmentation automatically when data exceeds MSS.
// =============================================================================

void RunTcpDataScenario(const std::string& outputPath)
{
    NS_LOG_INFO("=== Running TCP Data Transfer Scenario ===");
    NS_LOG_INFO("This scenario demonstrates TCP segmentation of large data.");
    NS_LOG_INFO("Open " << outputPath << "client-0-0.pcap in Wireshark.");
    NS_LOG_INFO("Count TCP segments with non-zero 'TCP segment Len'.");

    NodeContainer nodes;
    nodes.Create(2);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("100Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("2ms"));

    NetDeviceContainer devices = p2p.Install(nodes);

    InternetStackHelper internet;
    internet.Install(nodes);

    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    // TCP Server
    Address serverAddress(InetSocketAddress(interfaces.GetAddress(1), g_serverPort));
    PacketSinkHelper sinkHelper("ns3::TcpSocketFactory",
                                 InetSocketAddress(Ipv4Address::GetAny(), g_serverPort));
    ApplicationContainer serverApp = sinkHelper.Install(nodes.Get(1));
    serverApp.Start(Seconds(0.0));
    serverApp.Stop(Seconds(30.0));

    // =============================================================================
    // Relevant to [C]: Payload Size Configuration
    // BulkSendApplication sends g_payloadSize bytes (default: 50000)
    // This exceeds TCP MSS (~1460 bytes), forcing TCP to segment the data
    // into multiple TCP segments automatically.
    //
    // Relevant to [C]: The application writes all data to the socket at once.
    // TCP's segmentation is transparent to the application layer.
    // =============================================================================

    BulkSendHelper clientHelper("ns3::TcpSocketFactory", serverAddress);
    // Relevant to [C]: MaxBytes controls total data sent by application
    clientHelper.SetAttribute("MaxBytes", UintegerValue(g_payloadSize));
    // Relevant to [C]: SendSize is the application's write size, not TCP segment size
    clientHelper.SetAttribute("SendSize", UintegerValue(g_payloadSize));

    ApplicationContainer clientApp = clientHelper.Install(nodes.Get(0));
    clientApp.Start(Seconds(1.0));
    clientApp.Stop(Seconds(29.0));

    // =============================================================================
    // Relevant to [W]: PCAP captures all TCP segments
    // In Wireshark, you'll see:
    //   - Multiple segments with "TCP segment Len" showing bytes per segment
    //   - Sequence numbers incrementing by segment length
    //   - Receiver window size in ACK packets
    // =============================================================================

    p2p.EnablePcap(outputPath + "client", devices.Get(0), true);
    p2p.EnablePcap(outputPath + "server", devices.Get(1), true);

    Simulator::Stop(Seconds(32.0));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("TCP Data Transfer scenario complete.");
    NS_LOG_INFO("Payload size: " << g_payloadSize << " bytes");
    NS_LOG_INFO("Expected segments: ~" << (g_payloadSize / 1460 + 1) << " (MSS ~1460 bytes)");
}

// =============================================================================
// TCP LOSS AND RETRANSMISSION SCENARIO
// =============================================================================
// Relevant to [W]: Retransmissions visible in Wireshark as "TCP Retransmission"
// Can also identify by duplicate sequence numbers
//
// Relevant to [W]: Retransmission cause:
//   - If duplicate ACKs precede retransmission -> fast retransmit
//   - If delay before retransmission without duplicates -> timeout (Section 3.5.4)
//
// Relevant to [C]: The application does NOT detect or handle loss.
// TCP's reliability mechanism handles all loss detection and retransmission.
// =============================================================================

void RunTcpLossScenario(const std::string& outputPath)
{
    NS_LOG_INFO("=== Running TCP Loss/Retransmission Scenario ===");
    NS_LOG_INFO("This scenario induces packet loss to demonstrate TCP reliability.");
    NS_LOG_INFO("Open " << outputPath << "client-0-0.pcap in Wireshark.");
    NS_LOG_INFO("Look for 'TCP Retransmission' markers or duplicate sequence numbers.");

    NodeContainer nodes;
    nodes.Create(2);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("10ms"));

    NetDeviceContainer devices = p2p.Install(nodes);

    // =============================================================================
    // Relevant to [C]: RateErrorModel Configuration
    // The error model randomly drops packets with probability g_lossRate.
    // This simulates network packet loss to trigger TCP retransmissions.
    // TCP handles this transparently - the application is unaware of the loss.
    // =============================================================================

    Ptr<RateErrorModel> errorModel = CreateObject<RateErrorModel>();
    errorModel->SetAttribute("ErrorRate", DoubleValue(g_lossRate));
    errorModel->SetAttribute("ErrorUnit", EnumValue(RateErrorModel::ERROR_UNIT_PACKET));
    // Apply error model to server's receive path
    devices.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(errorModel));

    InternetStackHelper internet;
    internet.Install(nodes);

    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    // TCP Server
    Address serverAddress(InetSocketAddress(interfaces.GetAddress(1), g_serverPort));
    PacketSinkHelper sinkHelper("ns3::TcpSocketFactory",
                                 InetSocketAddress(Ipv4Address::GetAny(), g_serverPort));
    ApplicationContainer serverApp = sinkHelper.Install(nodes.Get(1));
    serverApp.Start(Seconds(0.0));
    serverApp.Stop(Seconds(60.0));

    // =============================================================================
    // Relevant to [C]: TCP Reliability
    // The client sends data without any knowledge of packet loss.
    // TCP's reliability mechanism automatically:
    //   1. Detects lost segments (via timeout or duplicate ACKs)
    //   2. Retransmits the lost data
    //   3. Ensures all data arrives at the receiver
    // =============================================================================

    BulkSendHelper clientHelper("ns3::TcpSocketFactory", serverAddress);
    // Larger payload increases chance of observable retransmissions
    clientHelper.SetAttribute("MaxBytes", UintegerValue(100000));
    clientHelper.SetAttribute("SendSize", UintegerValue(1400));

    ApplicationContainer clientApp = clientHelper.Install(nodes.Get(0));
    clientApp.Start(Seconds(1.0));
    clientApp.Stop(Seconds(59.0));

    // =============================================================================
    // Relevant to [W]: Analyzing Retransmissions in Wireshark
    // 1. Filter by "tcp.analysis.retransmission" to see only retransmissions
    // 2. Look at sequence numbers - retransmitted segments have same seq number
    // 3. Check if duplicate ACKs precede retransmission (fast retransmit)
    //    or if there's a timeout delay (RTO-based retransmission)
    // =============================================================================

    p2p.EnablePcap(outputPath + "client", devices.Get(0), true);
    p2p.EnablePcap(outputPath + "server", devices.Get(1), true);

    Simulator::Stop(Seconds(62.0));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("TCP Loss/Retransmission scenario complete.");
    NS_LOG_INFO("Loss rate: " << (g_lossRate * 100) << "%");
    NS_LOG_INFO("Hint: Filter 'tcp.analysis.retransmission' in Wireshark.");
}

// =============================================================================
// TCP CONGESTION CONTROL SCENARIO
// =============================================================================
// Relevant to [W]: Use Wireshark's Time-Sequence Graph (Stevens) to visualize:
//   Statistics -> TCP Stream Graphs -> Time-Sequence Graph (Stevens)
//
// Relevant to [W]: Slow start shows exponential growth (doubling each RTT)
// Congestion avoidance shows linear growth after ssthresh is reached
//
// Relevant to [B]: After loss, cwnd is reduced (typically halved)
// Visible as reduced slope in the time-sequence graph
//
// Relevant to [C]: TCP variant (e.g., NewReno) is configured using
// Config::SetDefault() before creating any TCP sockets
// =============================================================================

void RunTcpCongestionScenario(const std::string& outputPath)
{
    NS_LOG_INFO("=== Running TCP Congestion Control Scenario ===");
    NS_LOG_INFO("This scenario demonstrates TCP slow start and congestion avoidance.");
    NS_LOG_INFO("Open " << outputPath << "client-0-0.pcap in Wireshark.");
    NS_LOG_INFO("Use: Statistics -> TCP Stream Graphs -> Time-Sequence Graph (Stevens)");

    // =============================================================================
    // Relevant to [C]: TCP Variant Configuration
    // Config::SetDefault() sets the TCP congestion control algorithm BEFORE
    // any TCP sockets are created. TcpNewReno implements:
    //   - Slow start: cwnd doubles each RTT until ssthresh
    //   - Congestion avoidance: cwnd increases by 1 MSS per RTT
    //   - Fast retransmit: retransmit after 3 duplicate ACKs
    //   - Fast recovery: reduce cwnd to half, then linear increase
    // =============================================================================

    Config::SetDefault("ns3::TcpL4Protocol::SocketType", StringValue("ns3::TcpNewReno"));
    // Set initial cwnd to 1 segment for clearer slow start visualization
    Config::SetDefault("ns3::TcpSocket::InitialCwnd", UintegerValue(1));

    NodeContainer nodes;
    nodes.Create(2);

    // =============================================================================
    // Relevant to [T]: Link delay affects RTT
    // RTT = 2 * propagation_delay (for symmetric links)
    // Larger RTT means slower cwnd growth and longer timeout values
    // =============================================================================

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("5Mbps")); // Moderate bandwidth
    p2p.SetChannelAttribute("Delay", StringValue("20ms"));    // 40ms RTT

    NetDeviceContainer devices = p2p.Install(nodes);

    // Induce some loss to trigger congestion response
    Ptr<RateErrorModel> errorModel = CreateObject<RateErrorModel>();
    errorModel->SetAttribute("ErrorRate", DoubleValue(0.02)); // 2% loss
    errorModel->SetAttribute("ErrorUnit", EnumValue(RateErrorModel::ERROR_UNIT_PACKET));
    devices.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(errorModel));

    InternetStackHelper internet;
    internet.Install(nodes);

    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    // TCP Server
    Address serverAddress(InetSocketAddress(interfaces.GetAddress(1), g_serverPort));
    PacketSinkHelper sinkHelper("ns3::TcpSocketFactory",
                                 InetSocketAddress(Ipv4Address::GetAny(), g_serverPort));
    ApplicationContainer serverApp = sinkHelper.Install(nodes.Get(1));
    serverApp.Start(Seconds(0.0));
    serverApp.Stop(Seconds(120.0));

    // =============================================================================
    // Relevant to [B]: Long transfer to observe congestion window evolution
    // The time-sequence graph will show:
    //   - Initial exponential growth (slow start)
    //   - Transition to linear growth (congestion avoidance)
    //   - Drops in sending rate after packet loss
    // =============================================================================

    BulkSendHelper clientHelper("ns3::TcpSocketFactory", serverAddress);
    clientHelper.SetAttribute("MaxBytes", UintegerValue(500000)); // 500KB transfer
    clientHelper.SetAttribute("SendSize", UintegerValue(1400));

    ApplicationContainer clientApp = clientHelper.Install(nodes.Get(0));
    clientApp.Start(Seconds(1.0));
    clientApp.Stop(Seconds(119.0));

    p2p.EnablePcap(outputPath + "client", devices.Get(0), true);
    p2p.EnablePcap(outputPath + "server", devices.Get(1), true);

    Simulator::Stop(Seconds(122.0));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("TCP Congestion Control scenario complete.");
    NS_LOG_INFO("TCP Variant: TcpNewReno");
    NS_LOG_INFO("Hint: Use Wireshark -> Statistics -> TCP Stream Graphs -> Time-Sequence Graph (Stevens)");
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
// Relevant to [W]: IP header shows Protocol = 17 for UDP
//
// Relevant to [C]: UDP is connectionless - no handshake before sending data
// Compare with TCP's three-way handshake (Section 3.3)
// =============================================================================

void RunUdpBasicScenario(const std::string& outputPath)
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
    p2p.SetChannelAttribute("Delay", StringValue("2ms"));

    NetDeviceContainer devices = p2p.Install(nodes);

    InternetStackHelper internet;
    internet.Install(nodes);

    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    // =============================================================================
    // Relevant to [C]: UDP Server Setup
    // PacketSink with UdpSocketFactory creates a UDP socket.
    // Unlike TCP, there is no Listen() call - UDP just receives datagrams.
    // The server Bind()s to g_serverPort to receive incoming datagrams.
    // =============================================================================

    // UDP Server
    Address serverAddress(InetSocketAddress(interfaces.GetAddress(1), g_serverPort));
    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory",
                                 InetSocketAddress(Ipv4Address::GetAny(), g_serverPort));
    ApplicationContainer serverApp = sinkHelper.Install(nodes.Get(1));
    serverApp.Start(Seconds(0.0));
    serverApp.Stop(Seconds(30.0));

    // =============================================================================
    // Relevant to [C]: UDP Client Setup - Connectionless
    // OnOffApplication with UdpSocketFactory creates UDP datagrams.
    // Uses Socket::CreateSocket() followed by Bind() and SendTo().
    // NO Connect() or handshake - data is sent immediately.
    //
    // Relevant to [B]: Destination port (g_serverPort = 9) is visible in
    // Wireshark as the UDP destination port field.
    // =============================================================================

    OnOffHelper clientHelper("ns3::UdpSocketFactory", serverAddress);
    clientHelper.SetAttribute("DataRate", StringValue("1Mbps"));
    clientHelper.SetAttribute("PacketSize", UintegerValue(1024));
    clientHelper.SetAttribute("MaxBytes", UintegerValue(10240)); // 10 packets

    ApplicationContainer clientApp = clientHelper.Install(nodes.Get(0));
    clientApp.Start(Seconds(1.0));
    clientApp.Stop(Seconds(29.0));

    // =============================================================================
    // Relevant to [W]: Analyzing UDP in Wireshark
    // 1. Filter: "udp" to see only UDP packets
    // 2. IP header: Protocol field = 17 (decimal)
    // 3. UDP header shows all 4 fields
    // 4. Note: No SYN/ACK - data starts immediately
    // =============================================================================

    p2p.EnablePcap(outputPath + "client", devices.Get(0), true);
    p2p.EnablePcap(outputPath + "server", devices.Get(1), true);

    Simulator::Stop(Seconds(32.0));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("Basic UDP scenario complete.");
    NS_LOG_INFO("UDP destination port: " << g_serverPort);
    NS_LOG_INFO("Hint: Filter 'udp' in Wireshark to see UDP packets.");
}

// =============================================================================
// UDP LOSS SCENARIO
// =============================================================================
// Relevant to [W]: Lost UDP packets are NOT retransmitted
// Compare sent vs received packet count - they won't match
//
// Relevant to [B]: TCP vs UDP under loss:
//   - TCP: Retransmits lost segments, reduces sending rate
//   - UDP: No retransmission, no rate adaptation, packets lost permanently
//
// Relevant to [C]: UDP sender does NOT adapt transmission rate after loss
// There is no congestion control in UDP (Section 3.3)
// =============================================================================

void RunUdpLossScenario(const std::string& outputPath)
{
    NS_LOG_INFO("=== Running UDP Loss Scenario ===");
    NS_LOG_INFO("This scenario demonstrates UDP's lack of reliability.");
    NS_LOG_INFO("Open " << outputPath << "client-0-0.pcap in Wireshark.");
    NS_LOG_INFO("Compare packets sent vs received - lost packets are NOT retransmitted.");

    NodeContainer nodes;
    nodes.Create(2);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("10ms"));

    NetDeviceContainer devices = p2p.Install(nodes);

    // =============================================================================
    // Relevant to [C]: Same RateErrorModel as TCP scenario
    // The key difference: UDP does not detect or recover from this loss.
    // Lost packets are simply gone - no retransmission mechanism exists.
    // =============================================================================

    Ptr<RateErrorModel> errorModel = CreateObject<RateErrorModel>();
    errorModel->SetAttribute("ErrorRate", DoubleValue(g_lossRate));
    errorModel->SetAttribute("ErrorUnit", EnumValue(RateErrorModel::ERROR_UNIT_PACKET));
    devices.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(errorModel));

    InternetStackHelper internet;
    internet.Install(nodes);

    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    // UDP Server
    Address serverAddress(InetSocketAddress(interfaces.GetAddress(1), g_serverPort));
    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory",
                                 InetSocketAddress(Ipv4Address::GetAny(), g_serverPort));
    ApplicationContainer serverApp = sinkHelper.Install(nodes.Get(1));
    serverApp.Start(Seconds(0.0));
    serverApp.Stop(Seconds(60.0));

    // =============================================================================
    // Relevant to [C]: UDP Sender - No Rate Adaptation
    // Unlike TCP, the UDP sender continues at the same rate regardless of loss.
    // There is no feedback mechanism to detect congestion or packet loss.
    // This is by design - UDP trades reliability for simplicity and low overhead.
    //
    // Relevant to [B]: Compare with TCP Loss scenario:
    //   - TCP shows retransmissions and rate reduction
    //   - UDP shows steady sending rate, missing received packets
    // =============================================================================

    OnOffHelper clientHelper("ns3::UdpSocketFactory", serverAddress);
    clientHelper.SetAttribute("DataRate", StringValue("2Mbps"));
    clientHelper.SetAttribute("PacketSize", UintegerValue(1024));
    clientHelper.SetAttribute("MaxBytes", UintegerValue(102400)); // 100 packets

    ApplicationContainer clientApp = clientHelper.Install(nodes.Get(0));
    clientApp.Start(Seconds(1.0));
    clientApp.Stop(Seconds(59.0));

    // =============================================================================
    // Relevant to [W]: Analyzing UDP Loss in Wireshark
    // 1. Filter: "udp" and count packets at client (sent) vs server (received)
    // 2. Note: NO "Retransmission" markers - UDP doesn't have this concept
    // 3. Packet numbers may have gaps on server side due to loss
    // =============================================================================

    p2p.EnablePcap(outputPath + "client", devices.Get(0), true);
    p2p.EnablePcap(outputPath + "server", devices.Get(1), true);

    Simulator::Stop(Seconds(62.0));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("UDP Loss scenario complete.");
    NS_LOG_INFO("Loss rate: " << (g_lossRate * 100) << "%");
    NS_LOG_INFO("Hint: Compare UDP packet count in client vs server pcap files.");
}

// =============================================================================
// MAIN FUNCTION
// =============================================================================

int main(int argc, char* argv[])
{
    std::string scenario = "all";
    bool verbose = false;

    // =============================================================================
    // Relevant to [C]: Command-line argument parsing
    // --scenario selects which scenario to run
    // --verbose enables detailed logging
    // =============================================================================

    CommandLine cmd(__FILE__);
    cmd.AddValue("scenario", "Scenario: tcp-handshake, tcp-data, tcp-loss, tcp-congestion, "
                             "udp-basic, udp-loss, all", scenario);
    cmd.AddValue("verbose", "Enable verbose logging", verbose);
    cmd.AddValue("payloadSize", "TCP payload size for data transfer", g_payloadSize);
    cmd.AddValue("lossRate", "Packet loss rate (0.0-1.0)", g_lossRate);
    cmd.AddValue("serverPort", "Server port number", g_serverPort);
    cmd.Parse(argc, argv);

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
        if (scenario == s)
        {
            validScenario = true;
            break;
        }
    }
    if (!validScenario)
    {
        std::cerr << "Invalid scenario: " << scenario << std::endl;
        std::cerr << "Valid scenarios: tcp-handshake, tcp-data, tcp-loss, tcp-congestion, "
                     "udp-basic, udp-loss, all" << std::endl;
        return 1;
    }

    std::cout << "=== ns-3 TCP/UDP Lab ===" << std::endl;
    std::cout << "Scenario: " << scenario << std::endl;

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

    if (scenario == "tcp-handshake" || scenario == "all")
    {
        std::string outputPath = g_outputDir;
        if (scenario == "all")
        {
            outputPath = g_outputDir + "tcp-handshake/";
            std::filesystem::create_directories(outputPath, ec);
        }
        RunTcpHandshakeScenario(outputPath);
        success = success && VerifyPcapFile(outputPath + "client-0-0.pcap");
    }

    if (scenario == "tcp-data" || scenario == "all")
    {
        std::string outputPath = g_outputDir;
        if (scenario == "all")
        {
            outputPath = g_outputDir + "tcp-data/";
            std::filesystem::create_directories(outputPath, ec);
        }
        RunTcpDataScenario(outputPath);
        success = success && VerifyPcapFile(outputPath + "client-0-0.pcap");
    }

    if (scenario == "tcp-loss" || scenario == "all")
    {
        std::string outputPath = g_outputDir;
        if (scenario == "all")
        {
            outputPath = g_outputDir + "tcp-loss/";
            std::filesystem::create_directories(outputPath, ec);
        }
        RunTcpLossScenario(outputPath);
        success = success && VerifyPcapFile(outputPath + "client-0-0.pcap");
    }

    if (scenario == "tcp-congestion" || scenario == "all")
    {
        std::string outputPath = g_outputDir;
        if (scenario == "all")
        {
            outputPath = g_outputDir + "tcp-congestion/";
            std::filesystem::create_directories(outputPath, ec);
        }
        RunTcpCongestionScenario(outputPath);
        success = success && VerifyPcapFile(outputPath + "client-0-0.pcap");
    }

    if (scenario == "udp-basic" || scenario == "all")
    {
        std::string outputPath = g_outputDir;
        if (scenario == "all")
        {
            outputPath = g_outputDir + "udp-basic/";
            std::filesystem::create_directories(outputPath, ec);
        }
        RunUdpBasicScenario(outputPath);
        success = success && VerifyPcapFile(outputPath + "client-0-0.pcap");
    }

    if (scenario == "udp-loss" || scenario == "all")
    {
        std::string outputPath = g_outputDir;
        if (scenario == "all")
        {
            outputPath = g_outputDir + "udp-loss/";
            std::filesystem::create_directories(outputPath, ec);
        }
        RunUdpLossScenario(outputPath);
        success = success && VerifyPcapFile(outputPath + "client-0-0.pcap");
    }

    std::cout << std::endl;
    std::cout << "=== Simulation Complete ===" << std::endl;
    std::cout << "PCAP files written to: " << g_outputDir << std::endl;

    if (scenario == "all")
    {
        std::cout << "Subfolders created for each scenario." << std::endl;
    }

    std::cout << std::endl;
    std::cout << "=== Analysis Hints ===" << std::endl;
    std::cout << "- TCP Handshake: Look for SYN, SYN-ACK, ACK flags" << std::endl;
    std::cout << "- TCP Data: Count segments with non-zero 'TCP segment Len'" << std::endl;
    std::cout << "- TCP Loss: Filter 'tcp.analysis.retransmission'" << std::endl;
    std::cout << "- TCP Congestion: Statistics -> TCP Stream Graphs -> Time-Sequence Graph (Stevens)" << std::endl;
    std::cout << "- UDP Basic: Inspect 4-field UDP header, Protocol=17" << std::endl;
    std::cout << "- UDP Loss: Compare packet counts (no retransmissions)" << std::endl;

    if (!success)
    {
        std::cerr << "ERROR: One or more PCAP files failed verification!" << std::endl;
        return 1;
    }

    return 0;
}
