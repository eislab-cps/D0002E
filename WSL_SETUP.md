# Windows WSL Setup Guide

This is the recommended setup if you are using Windows.

It gives you:

- Ubuntu Linux for building and running `ns-3`
- Windows Wireshark for opening the generated `.pcap` files
- One clean lab checkout directly inside `ns-3`

This guide was written against the official Microsoft WSL install docs and the
official ns-3 Linux installation guide.

## What you need

- Windows 10 version 2004 or later, or Windows 11
- Administrator access for the initial WSL install
- Internet access to download WSL, Ubuntu, ns-3, and this repository

## Important recommendation

Do your Linux work inside the WSL Linux filesystem, for example under
`/home/<your-user>/`.

Do not build `ns-3` under `/mnt/c/...`.

That path works, but it is slower and tends to cause a worse experience when
building Linux projects from WSL.

## Step 1: Install WSL and Ubuntu

Open **PowerShell as Administrator** and run:

```powershell
wsl --install -d Ubuntu
```

Then restart Windows if prompted.

After the restart:

1. Open `Ubuntu` from the Start menu.
2. Wait for the first-time setup to finish.
3. Create your Linux username and password when asked.

## Step 2: Verify WSL is working

In PowerShell, run:

```powershell
wsl -l -v
```

You should see an `Ubuntu` entry, usually using WSL version `2`.

Then open Ubuntu and run:

```bash
uname -a
```

If that prints Linux system information, WSL is working.

## Step 3: Install the Linux packages needed for ns-3

Run these commands inside Ubuntu:

```bash
sudo apt update
sudo apt install -y g++ python3 cmake ninja-build git wget
```

## Step 4: Create a workspace inside WSL

Still inside Ubuntu:

```bash
mkdir -p ~/courses
cd ~/courses
```

You can choose another folder name if you want, but keep it under your Linux
home directory.

## Step 5: Download and unpack ns-3

Inside Ubuntu:

```bash
wget https://www.nsnam.org/releases/ns-allinone-3.46.1.tar.bz2
tar xjf ns-allinone-3.46.1.tar.bz2
cd ns-allinone-3.46.1/ns-3.46.1
```

## Step 6: Clone this lab repository directly into `scratch/d0002e`

From the `ns-3.46.1` root:

```bash
git clone https://github.com/eislab-cps/D0002E.git scratch/d0002e
```

This is the easiest layout for these labs because the build targets and README
commands already assume that exact path.

## Step 7: Configure and build ns-3

Still in the `ns-3.46.1` root:

```bash
./ns3 configure --enable-examples
./ns3 build
```

The build takes a while the first time.

## Step 8: Verify the install

Run one standard ns-3 example first:

```bash
./ns3 run first
```

Then run one D0002E lab:

```bash
./ns3 run "scratch/d0002e/lab1-with-guidance --scenario=basic"
```

If that succeeds, your setup is ready.

## Step 9: Open the generated PCAP files in Wireshark on Windows

Install Wireshark on Windows if you do not already have it:

- <https://www.wireshark.org/download.html>

After you run a lab in WSL, open the current WSL folder in Windows Explorer:

```bash
explorer.exe .
```

From there you can browse to the output folders and open `.pcap` files with
Wireshark.

Common output locations:

- Lab 1: `scratch/d0002e/lab 1 output/`
- Lab 2: `scratch/d0002e/lab 2 output/`
- Lab 3: `scratch/d0002e/lab 3 output/`
- Lab 4: `scratch/d0002e/lab 4 output/`
- Lab 5: `scratch/d0002e/lab 5 output/`
- Lab 6: `scratch/d0002e/lab 7 output/`

Note:

- Lab 6 uses the correct executable name, `lab6-with-guidance`.
- Its TLS capture output still goes into `lab 7 output/` for compatibility with
  the existing lab material.

## Typical workflow after setup

Each time you want to work on the labs:

```bash
cd ~/courses/ns-allinone-3.46.1/ns-3.46.1
./ns3 run "scratch/d0002e/lab1-with-guidance --scenario=basic"
```

Then open the generated capture in Wireshark from Windows.

## Troubleshooting

### `wsl --install` prints help text instead of installing

WSL may already be installed.

Try:

```powershell
wsl -l -v
wsl --update
```

Then start Ubuntu from the Start menu.

### `./ns3 run ...` says the target does not exist

You are usually in one of these situations:

- You are not in the `ns-3.46.1` root directory
- The lab repo is not at `scratch/d0002e`
- You forgot to rebuild after adding the lab files

From the `ns-3.46.1` root, run:

```bash
./ns3 configure --enable-examples
./ns3 build
```

### The build is very slow

Check where your files are stored.

Good:

```bash
/home/<your-user>/courses/ns-allinone-3.46.1/ns-3.46.1
```

Avoid:

```bash
/mnt/c/Users/<your-user>/...
```

### Windows Wireshark cannot find your files

From the correct directory inside WSL, run:

```bash
explorer.exe .
```

That opens the WSL folder in Windows Explorer so you can open the `.pcap` files
directly.

## Official references

- Microsoft WSL install guide: <https://learn.microsoft.com/en-us/windows/wsl/install>
- Microsoft guidance on WSL file storage and `explorer.exe .`:
  <https://learn.microsoft.com/en-us/windows/wsl/filesystems>
- ns-3 Linux installation guide:
  <https://www.nsnam.org/docs/installation/html/linux.html>
