# 🌐 D0002E Computer Networking — Lab Simulations

> **Luleå University of Technology**
>
> This repository contains **ns-3 simulation scripts** and lab questions for 6 labs covering Chapters 2–6 and 8 of Kurose & Ross, *Computer Networking: A Top-Down Approach* (8th edition). Each lab generates PCAP files that you analyze in **Wireshark** to answer questions about network protocol behavior.

---

## 📋 Prerequisites

To complete these labs, you will need:

- 📖 **Textbook:** Kurose & Ross, *Computer Networking: A Top-Down Approach*, 8th edition. *(Chapter numbers may vary between editions)*
- 🦈 **Wireshark:** Free packet analyzer. [Download here](https://www.wireshark.org/download.html).
- 🛠️ **ns-3.46:** Network simulator. *(Setup instructions below)*

> [!TIP]
> **Windows users:**
> If you are on Windows, we heavily recommend using **WSL with Ubuntu** and running `ns-3` inside WSL. 
> 
> 📚 **[Windows WSL Setup Guide](WSL_SETUP.md)**
> 
> This is the recommended setup because these labs are Linux-based, but the generated `.pcap` files still open perfectly in your native Windows Wireshark.

---

## 🚀 ns-3 Setup Guide

### 1. System Requirements

🐧 **Linux is required.** Ubuntu 22.04 or 24.04 are recommended and known to work flawlessly.

### 2. Install Dependencies

Open your terminal and install the required tools:

```bash
sudo apt update
sudo apt install g++ python3 cmake ninja-build git wget
```

### 3. Download and Build ns-3

Download and extract the `ns-3.46.1` source, then build the simulator:

```bash
# Download and extract ns-allinone-3.46.1
wget https://www.nsnam.org/releases/ns-allinone-3.46.1.tar.bz2
tar xvf ns-allinone-3.46.1.tar.bz2
cd ns-allinone-3.46.1/ns-3.46.1

# Configure and build
./ns3 configure --enable-examples
./ns3 build
```

### 4. Place the Lab Files

Clone this repository directly into the `scratch/d0002e/` directory inside your `ns-3` tree.

```bash
# From the ns-3 root (ns-allinone-3.46.1/ns-3.46.1/):
git clone https://github.com/eislab-cps/D0002E.git scratch/d0002e
```

**After cloning, your structure should look like this:**
```text
ns-3.46.1/scratch/d0002e/
├── CMakeLists.txt
├── lab1-http-dns/
├── lab2-tcp-udp/
├── lab3-ip-dataplane/
├── lab4-ip-controlplane/
├── lab5-link-layer/
└── lab6-tls/
```

Then rebuild `ns-3` so it registers the new examples:

```bash
./ns3 configure --enable-examples
./ns3 build
```

### 5. Verify the Installation

Run a default `ns-3` example to ensure everything works:

```bash
./ns3 run first
```

Then try running the first lab simulation:

```bash
./ns3 run "scratch/d0002e/lab1-with-guidance --scenario=basic"
```

---

## 🎓 Student Notes & Best Practices

- 💻 Run `ns-3` strictly from Linux or WSL, **not** native Windows.
- 📁 **WSL Users:** Keep the project under your Linux home directory (`/home/<user>/...`), **not** under the mounted Windows drive (`/mnt/c/...`).
- 🛑 Generated output folders and PCAP files are local artifacts. **Do not commit them** back to the repository.
- 🎲 The lab scripts use reproducible seeds and write captures under seed-specific output folders (e.g., `scratch/d0002e/lab 2 output/seed42/`).
- 🎥 Labs 2, 3, 5, and 6 write `netanim.xml` files alongside the PCAP captures. This requires an `ns-3` build with the `netanim` module enabled.
- 🔒 **Lab 6 Note:** Uses the executable name `lab6-with-guidance`, but its TLS capture output is written under `scratch/d0002e/lab 7 output/`.

---

## 📂 Repository Structure

```text
README.md                              ← This file
WSL_SETUP.md                           ← Windows + WSL setup guide
CMakeLists.txt                         ← ns-3 build configuration for all labs
.gitignore
lab1-http-dns/
  README.md                            ← Lab 1 instructions and questions
  lab1-with-guidance.cc                ← Lab 1 simulation source
lab2-tcp-udp/
  README.md                            ← Lab 2 instructions and questions
  lab2-with-guidance.cc                ← Lab 2 simulation source
lab3-ip-dataplane/
  README.md                            ← Lab 3 instructions and questions
  lab3-with-guidance.cc                ← Lab 3 simulation source
lab4-ip-controlplane/
  README.md                            ← Lab 4 instructions and questions
  lab4-with-guidance.cc                ← Lab 4 simulation source
lab5-link-layer/
  README.md                            ← Lab 5 instructions and questions
  lab5-with-guidance.cc                ← Lab 5 simulation source
lab6-tls/
  README.md                            ← Lab 6 instructions and questions
  lab6-with-guidance.cc                ← Lab 6 simulation source
```

---

## 🔬 Lab Curriculum Overview

| Lab | Topic | Chapter | Questions |
|:---:|:---|:---:|:---:|
| **1** | 🌐 HTTP and DNS | 2 | 25 |
| **2** | 🔄 TCP and UDP | 3 | 19 |
| **3** | 🔀 IP Data Plane | 4 | 10 |
| **4** | 🗺️ IP Control Plane | 5 | 12 |
| **5** | 🔗 Link Layer and LANs | 6 | 16 |
| **6** | 🔒 Transport Layer Security | 8 | 13 |
| | **Total** | | **95** |

---

## 🏷️ Question Tag Legend

Each question in the labs is tagged to indicate how you should approach answering it:

| Tag | Methodology |
|:---:|:---|
| `[W]` | 🦈 Answer using Wireshark capture analysis |
| `[C]` | 💻 Answer by reading the simulation source code (`labN-with-guidance.cc`) |
| `[B]` | 🦈+💻 Answer using *both* Wireshark and source code |
| `[T]` | 📖 Answer from textbook theory |
| `[V]` | ✅ Verify Wireshark observations against textbook explanations |
| `[_+X]`| 🧪 *Experiment!* In addition to what is instructed at "_", experiment with different input parameters |

---

## 🏃‍♀️ How to Work Through a Lab

1. 📖 **Read** the lab `README.md` in the corresponding directory.
2. 🔍 **Examine** the `.cc` source file — the top comments describe the network topology, available scenarios, and expected output.
3. 🏗️ **Build and run** the simulation using the commands provided in the lab README.
4. 🦈 **Open** the generated `.pcap` files in Wireshark.
5. ✍️ **Answer** the questions applying the technique indicated by each question's tag.
