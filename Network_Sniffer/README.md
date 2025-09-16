***CodeAlpha_Basic_Network_Sniffer***

Task 1 in CodeAlpha's Cyber Security Internship

***OverView***

A simple Python script designed to monitor and interpret network traffic in real time, helping users understand how packets are formed and transmitted.

***Requirements***

 **•** Scapy library (pip install scapy)

 **•** Npcap (Nmap Packet Capture Library) or WinPcap but less preferrable

 ***Usage***

 1. Clone the repository:

     git clone https://github.com/M7amed0x/codealpha_tasks/tree/main/Network_Sniffer

 4. python3 script.py

***Features***


**•** Packet Capture: Utilizes the Scapy library to capture network packets in real-time.

**•** Packet Analysis: Parses captured packets to extract and display relevant information such as Ethernet frame details, IPv4 packet details (including ICMP, TCP, and UDP), etc.

**•** Error Handling: Implements robust error handling mechanisms using try-except blocks to gracefully handle exceptions that may occur during packet processing or sniffing.

**•** Customization: Easily customizable with options to configure capture timeout, output format, and more.
