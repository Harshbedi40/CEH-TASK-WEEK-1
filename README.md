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

* The cyber kill chain methodology is a component of intelligence-driven defense for the identification and prevention of malicious
intrusion activities
* It provides greater insight into attack phases, which helps security professionals to understand the adversary's tactics, techniques,
and procedures beforehand

# Steps of Cyber Kill Chain Methodology -:

* Reconnaissance -> Gather data on the target to probe for weak points
* Wepanization -> Create a deliverable malicicous payload using an exploit and a backdoor
* Delivery -> Send weaponized bundle to the victim using email, USB, etc.
* Exploitation -> Exploit a vulnerability by executing code on the victim's system
* Installation -> Install malware on the target system
* Command and Control -> Create a command and control channel to communicate and pass data back and forth
* Action of Objective -> Perform actions to achieve intended objectives/goals

# What do you understand about Mitre Attack Framework & TTPs? Explain in detail.

# Mitre Attack Framework 

* MITRE ATT&CK is a globally accessible knowledge base of adversary tactics and techniques based on real-world observations
* The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the
private sector, government, and the cybersecurity product and service community
* The 14 tactic categories within ATT&CK for Enterprise are derived from the later stages (exploit, control, maintain, and
execute) of the seven stages of the Cyber Kill Chain

* Pre Attack -> Recon , Weaponize
* Enterprise Attack -> Deliver , Exploit , Control , Execute , Maintain

# The following are the tactics in ATT&CK for Enterprise
* Reconnaissance
* Resource Development
* Initial Access
* Execution
* Persistence
* Privilege Escalation
* Defense Evasion
* Credential Access
* Discovery
* Lateral Movement
* Collection
* Command and Control
* Exfiltration
* Impact

# MITRE ATT&CK is categorized into different matrices based on attack environments:

* Enterprise Matrix: Focuses on Windows, Linux, macOS, Cloud, and Containers.
* Mobile Matrix: Covers attack techniques on mobile platforms (Android & iOS).
* ICS (Industrial Control Systems) Matrix: Addresses threats in industrial environments.

# Tactics, Techniques, and Procedures (TTPs)

The term Tactics, Techniques, and Procedures (TTPs) refers to the patterns of activities and methods associated with specific threat actors or groups of threat actors

# Tactics 

* "Tactics" are the guidelines thatdescribe the way an attacker performs the attack from beginning to the end
* This guideline consists of the various tactics for information gathering to perform initial exploitation, privilege escalation, and lateral movement, and to deploy measures for persistent access to the system and other purposes

# Techniques 

* "Techniques" are the technical methods used by an attacker to achieve intermediate results during the attack
* These techniques include initial exploitation, setting up and maintaining command and control channels, accessing the target infrastructure, covering the tracks of data exfiltration and others

# Procedures 

* "Procedures" are organizational approaches that threat actors follow to launch an attack
* The number of actions usually differs depending on the objectives of the procedure and threat actor group

# Describe the Footprinting techniques & types of footprinting along with tools used in it.

Footprinting is the process of gathering information about a target system, network, or organization before launching an attack. It helps attackers and security professionals understand the target’s infrastructure, identify vulnerabilities, and plan further actions.

# why footprinting is important 
* For Hackers: Used to gather intelligence and find weaknesses to exploit.
* For Ethical Hackers & Security Teams: Helps in penetration testing, identifying security gaps, and strengthening defenses.

# Types of Footprinting 
Footprinting is classified into two main types based on the approach used:

1. Active Footprinting

* Involves direct interaction with the target system to gather information.
* Can be easily detected by security teams.
* Example: Scanning ports using Nmap, sending ping requests.

2. Passive Footprinting

* Involves gathering information without directly interacting with the target.
* Difficult to detect since it relies on publicly available data.
* Example: Checking WHOIS records, searching social media profiles.

# Footprinting Tools and Techniques 

1. Search Engine Footprinting
* Tools: Google, Bing, Shodan, Google Dorks
* Description -> Hackers use advanced search queries (Google Dorks) to find sensitive information exposed on websites.
* Example -> Searching for exposed admin login pages or confidential files.

2. WHOIS & Domain Footprinting
* Tools: WHOIS Lookup, ICANN, Domain Dossier
* Description -> WHOIS lookup provides domain registration details, including:

* Owner's name, email, and phone number
* Domain creation & expiration date
* DNS and IP address details

3. DNS Footprinting
* Tools: nslookup, dig, DNSDumpster, Fierce
* Description -> Identifies DNS records such as A, MX, TXT, and CNAME records.
Helps attackers understand the domain structure and potential subdomains.

4. Email Footprinting
* Tools: Email Tracker Pro, EmailHeaderAnalyzer
* Description -> Extracts metadata from email headers, revealing IP addresses, mail servers, and routing paths.
Helps in tracking email origins and understanding email security settings.

5. Social Media & Public Records Footprinting
* Tools: Maltego, Social Searcher, SpiderFoot
* Description -> Hackers gather employee details, job roles, and company insights from:
  
* LinkedIn
* Facebook
* Twitter
Example -> Searching for company executives who may be targeted for spear phishing.

6. Network Footprinting
* Tools: Nmap, Angry IP Scanner, Netcraft
* Description -> Identifies active hosts, open ports, and running services.

7. Website Footprinting
* Tools: Wappalyzer, BuiltWith, HTTrack
* Description -> Identifies technologies used on a website (e.g., CMS, framework, plugins).
HTTrack allows hackers to clone entire websites for offline analysis.

9. Dark Web & Underground Forums Footprinting
* Tools: Tor Browser, Ahmia Search Engine
* Description -> Attackers browse the dark web to find leaked databases, compromised credentials, and underground hacking discussions.

# List 15 Google dorking operators along with their use

# Googlke Dorking 
Google Dorking (also known as Google Hacking) uses advanced search queries to find hidden or sensitive information that is not easily accessible through normal search. These operators help ethical hackers, penetration testers, and OSINT professionals gather data efficiently.

# Here are the list of 15 Google Dork and their use -:

1. site: – Search Within a Specific Website

* Use: Find pages within a specific website.
* Example -> site:example.com  

2. intitle: – Find Pages with a Specific Title

* Use: Search for web pages with specific words in the title.
* Example -> intitle:"admin login"  

3. allintitle: – Search for Multiple Words in the Title

* Use: Finds pages that contain all the specified words in the title.
* Example -> allintitle:"phpmyadmin login"  
(Finds login pages for phpMyAdmin databases)

4. inurl: – Find URLs with a Specific Word

* Use: Searches for keywords within URLs.
* Example -> inurl:admin  
(Finds pages with "admin" in the URL, possibly leading to admin panels)

5. allinurl: – Search for Multiple Words in URL

* Use: Finds pages that contain all specified words in the URL.
* Example -> allinurl:login.php  
(Finds login pages that contain "login.php" in the URL)

6. filetype: – Search for Specific File Types

* Use: Finds specific file formats like PDF, DOC, XLS, etc.
* Example -> filetype:pdf "financial report"  
(Searches for financial reports in PDF format)

7. ext: – Search for Specific File Extensions

* Use: Similar to filetype:, but searches for file extensions.
* Example -> ext:docx "confidential"  
(Finds confidential Word documents)

8. intext: – Search for Specific Words in the Page Content

* Use: Finds pages that contain a specific word or phrase in the text.
* Example -> intext:"SQL injection vulnerability"  
(Finds pages discussing SQL injection vulnerabilities)

9. allintext: – Search for Multiple Words in Page Content

*Use: Finds pages that contain all specified words in the text.
* Example -> allintext:"username password login"  
(Searches for pages containing login details)

10. cache: – View Google’s Cached Version of a Page

* Use: Retrieves the last cached version of a webpage.
* Example -> cache:example.com  
(Shows Google's last saved version of example.com)

11. related: – Find Similar Websites

* Use: Finds sites similar to a given domain.
* Example -> related:github.com  
(Finds websites similar to GitHub)

12. link: – Find Pages Linking to a Website (Deprecated)

* Use: Used to find backlinks to a specific site. (Less effective now)
* Example -> link:example.com  
(Shows websites linking to example.com)

13. define: – Find Definitions of Words
* Use: Finds dictionary definitions of words.
* Example -> define:phishing  
(Displays the definition of "phishing")

14. before: and after: – Search Within a Date Range
* Use: Finds pages published before or after a specific date.
* Example -> hacking tutorial before:2020  
(Searches for hacking tutorials published before 2020)

🔹 Find cyberattack reports after 2022:

nginx
Copy
Edit
cyber attack report after:2022  

15. OR & AND – Combine Search Queries

* Use: Finds results that match either or both search terms.
* Example -> hacking OR pentesting  
(Finds pages that contain either "hacking" or "pentesting")

* Find login pages related to both admin and password:
* intitle:admin AND intext:password  
