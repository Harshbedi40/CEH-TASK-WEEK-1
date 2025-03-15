# CEH-TASK-WEEK-1 
# Discuss TCP & UDP Protocols and mention the difference between the two along with examples where they are used?
# 1. TCP (Transmission Control Protocol)
TCP is a connection-oriented protocol, meaning it establishes a reliable connection before transmitting data. It ensures data integrity and delivery in the correct order.
# Examples of TCP Usage:
* Web Browsing (HTTP/HTTPS) → Ensures web pages load completely and correctly.
* Email (SMTP, IMAP, POP3) → Reliable delivery of email messages.
* File Transfer (FTP, SFTP) → Ensures proper file transfer without corruption.
* Remote Login (SSH, Telnet) → Secure and reliable remote access.
# 2. UDP (User Datagram Protocol)
UDP is a connectionless protocol, meaning it sends data without ensuring its arrival or order. It is faster but does not guarantee reliability.
# Examples of UDP Usage:
* Online Gaming → Fast response times, slight data loss is tolerable.
* Video & Audio Streaming (YouTube, Netflix, VoIP) → Reduces delay in live broadcasts.
* DNS (Domain Name System) → Resolves domain names quickly without needing reliability.
* DHCP (Dynamic Host Configuration Protocol) → Quickly assigns IP addresses to devices.
# Key Differences Between TCP and UDP
# Feature	TCP (Transmission Control Protocol)	UDP (User Datagram Protocol)
* Type ->	Connection-oriented	Connectionless
Reliability	-> * Reliable (ensures data is received correctly)            	     * Unreliable (no guarantee of delivery)
Speed	-> * Slower due to error checking and retransmission	                     * Faster due to minimal overhead
Error Checking ->	* Uses checksums, acknowledgments, and retransmission   	     * Uses checksums but no retransmission
Order of Data	-> * Data arrives in order	                                       * Data may arrive out of order
Use Case	-> * When reliability matters (e.g., web browsing, file transfer)	     *When speed matters more than reliability (e.g., gaming, streaming)
# List the TCP Flags along with their use/function?
# List of TCP Flags and Their Functions 🚀
TCP (Transmission Control Protocol) uses flags to control the flow of data and manage connections. These flags are present in the TCP header and help determine the state of the connection between sender and receiver.
1. SYN (Synchronize)
* Function: Initiates a connection between two devices.
* Usage: Used in the three-way handshake process to establish a TCP connection.
* Example: Sent by the client to the server when opening a new connection.
2. ACK (Acknowledgment)
* Function: Acknowledges the receipt of data.
* Usage: Used in response to SYN, FIN, and data packets to confirm successful receipt.
* Example: If a client sends data, the server responds with an ACK to confirm it was received.
3. FIN (Finish)
* Function: Gracefully terminates a connection.
* Usage: Used when one side wants to end the communication.
* Example: When a client is done sending data, it sends a FIN flag to close the connection.
4. RST (Reset)
* Function: Abruptly resets the connection.
* Usage: Used to immediately terminate an unwanted or incorrect connection.
* Example: If a server receives a request for a closed port, it responds with RST.
5. PSH (Push)
* Function: Forces immediate delivery of data.
* Usage: Used when data needs to be processed immediately instead of waiting for a full buffer.
* Example: Used in real-time applications like live chat or voice calls.
6. URG (Urgent)
* Function: Indicates urgent data that should be processed immediately.
* Usage: Used when certain critical data needs to be prioritized over regular data.
* Example: Used in network control messages where quick action is needed.
7. CWR (Congestion Window Reduced)
* Function: Informs the sender that the receiver has reduced its congestion window due to network congestion.
* Usage: Helps in congestion control to avoid packet loss.
* Example: Used when TCP detects congestion and slows down data transmission.
8. ECE (Explicit Congestion Notification Echo)
* Function: Used to indicate network congestion without dropping packets.
* Usage: Works with CWR to handle congestion efficiently.
* Example: Helps in modern networks to avoid excessive packet loss.
# Summary Table: TCP Flags and Their Functions
* Flag ->	Full Form	Function
* SYN	 -> Synchronize	Initiates a connection
* ACK	 -> Acknowledgment	Confirms data receipt
* FIN	 -> Finish	Gracefully closes a connection
* RST	 -> Reset	Abruptly terminates a connection
* PSH	 -> Push	Forces immediate data delivery
* URG	 -> Urgent	Prioritizes urgent data
* CWR	 -> Congestion Window Reduced	Helps manage network congestion
* ECE	 -> Explicit Congestion Notification Echo	Signals congestion detection
# TCP Three-Way Handshake Using Flags
Client → Server: SYN (Request connection)
Server → Client: SYN-ACK (Acknowledge request)
Client → Server: ACK (Confirm connection is established)
# What is the difference in executing nmap as root user and as normal user? Give the flagsin nmap which require root permission to be performed?
# Difference Between Running Nmap as a Root User vs. Normal User
Nmap (Network Mapper) is a powerful network scanning tool that behaves differently when executed as a root user (administrator) versus a normal user (non-root). The key difference lies in the ability to send and manipulate raw packets, which is restricted to root users.
# 1. Running Nmap as a Root User
* When running Nmap as root, it has full privileges, allowing it to use advanced scanning techniques that require sending raw packets.
* It provides more accurate and faster results.
* Can perform stealth scans, OS detection, and use custom packet options.
  # Capabilities as Root User:
* Sends raw packets (bypassing normal socket-based restrictions).
* Uses SYN scans (stealthier and faster than full connect scans).
* Can perform OS fingerprinting and version detection more effectively.
* Can use certain NSE scripts that require lower-level access.
# 2. Running Nmap as a Normal User
* A normal user does not have permission to send raw packets.
* Many advanced scanning techniques are disabled.
* Relies on standard system calls to establish connections, making scans slower and more detectable.
  # Capabilities as Normal User:
* Can only perform TCP Connect scans (-sT), which are slower and more easily detected.
* Cannot use SYN scan (-sS) or any raw packet techniques.
* Some NSE scripts that require root privileges may not function properly.
# Nmap Flags That Require Root Privileges
Flag	           Scan Type	                                Description
-sS	             SYN Scan (Stealth Scan)	                  Sends SYN packets without completing the handshake. Faster and stealthier.
-sF	             FIN Scan	                                  Sends TCP FIN packets to determine open/closed ports.
-sX	             Xmas Scan	                                Sends packets with FIN, URG, and PSH flags set.
-sN	             NULL Scan	                                Sends packets with no flags set to detect open ports.
-O	            OS Detection	                              Identifies the target OS using fingerprinting techniques.
-sA	            ACK Scan	                                  Used for firewall analysis and filtering detection.
-sM	            Maimon Scan	                                Similar to FIN scan, used for bypassing certain firewalls.
-sI	            Idle Scan	                                  Uses a third-party zombie host for stealth scanning.
--packet-trace	Packet Tracing	                            Displays raw packets sent and received.
--spoof-mac    	MAC Address Spoofing	                      Changes the MAC address to hide identity.
-sU	            UDP Scan	                                  Scans for open UDP ports.
# Important points 
* Running Nmap as root unlocks advanced scanning techniques and provides better stealth, accuracy, and efficiency.
* Running Nmap as a normal user is limited to basic TCP connect scans (-sT) and lacks advanced features.
* Flags like -sS, -O, -sF, and -sX require root privileges for raw packet access.
* sudo nmap -sS -O -p- 192.168.1.1 ( Nmap command to run it with root privileges )


# Week-2 
# Task-1
# Here are some Social Engineering ( Phishing ) terms and thier definations :
* Phishing – A cyber attack where attackers send fraudulent emails pretending to be from a trusted source to trick users into revealing sensitive information like passwords, credit card details, or login credentials.

* Spear-phishing –> A targeted form of phishing that is personalized for a specific individual, organization, or business to make the scam more convincing and increase the chances of success.

* Vishing (Voice Phishing) –> Social engineering attacks conducted over the phone, where attackers pretend to be legitimate authorities (such as banks or tech support) to trick victims into providing sensitive information.

* Smishing (SMS Phishing) –> A phishing attack that occurs via SMS (text messages), where attackers send fake messages containing malicious links or requests for personal information.

* Quishing (QR Code Phishing) –> A newer type of phishing attack where cybercriminals use malicious QR codes to redirect users to fraudulent websites to steal credentials or infect devices.

* Shoulder Surfing –> A tactic where an attacker spies on someone’s screen or keyboard (in public places like cafes or ATMs) to steal sensitive information such as passwords or PINs.

* Tailgating –> A physical security breach where an unauthorized person follows an authorized individual into a restricted area without proper credentials, often relying on courtesy.

* Piggybacking –> Similar to tailgating, but in this case, the unauthorized person gains access with the consent of the authorized person (e.g., an employee holding the door open for someone pretending to be a visitor).

* Dumpster Diving –> A method where attackers search through discarded documents, hard drives, or electronic waste to find sensitive information that can be used for malicious purposes.

* Impersonation –> An attack where a cybercriminal pretends to be a trusted person (such as a boss, IT staff, or government official) to manipulate victims into providing access or sensitive data.

* Whaling –> A type of spear-phishing attack that specifically targets high-profile individuals such as CEOs, CFOs, or other executives to steal large amounts of money or confidential data.

* Quid Pro Quo –> A type of attack where cybercriminals offer something valuable (e.g., free software, tech support, or rewards) in exchange for confidential information.

* Baiting –> A tactic where attackers lure victims into downloading malicious files or clicking harmful links by promising something appealing, like free movies, software, or job offers.

* Hoax –> False information spread with the intent of misleading people, often to create panic, manipulate behavior, or lead victims into scams.

* Pretexting –> A social engineering technique where an attacker fabricates a story or scenario to gain a victim’s trust and extract sensitive information (e.g., pretending to be a bank representative asking for account details).

* Honeytrap –> A form of social engineering where an attacker uses romantic or flirtatious tactics to manipulate a victim into revealing confidential information or performing actions that compromise security.

# Task-4

# Explain the Cyber Kill Chain Methodology.







