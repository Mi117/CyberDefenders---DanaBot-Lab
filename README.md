CyberDefenders-DanaBot-Lab_Walkthorugh

INTRO:

This repository contains a walkthrough for the CyberDefenders "[DanaBot](https://cyberdefenders.org/blueteam-ctf-challenges/danabot/)" challenge.  DanaBot is a sophisticated banking trojan known for stealing financial information and credential harvesting. This challenge tasks blue teamers with analyzing a network capture (PCAP) to identify the infection vector, command-and-control (C2) communication, and other malicious activities associated with a DanaBot infection.

SCENARIO:

The SOC team has detected suspicious activity in the network traffic, revealing that a machine has been compromised. Sensitive company information has been stolen. Your task is to use Network Capture (PCAP) files and Threat Intelligence to investigate the incident and determine how the breach occurred.
For this Lab we will use the following tools:

- VIRUS TOTAL [https://www.virustotal.com/gui/]: for identifying details about the malware, by submitting the file(s) hashes to get comprehensive scan results and analysis.
- WIRESHARK [[https://www.wireshark.org/]: network protocol analyzer.
- NETWORK MINER [https://www.netresec.com/?page=NetworkMiner]: open source network forensics tool that extracts artifacts, such as files, images, emails and passwords, from captured network traffic in PCAP files.

!BEFORE STARTING!:

Safety first! When working with lab/challenge files from CyberDefenders (or any educational lab/challenge/range), it’s important to be responsible and stay safe by interacting with potentially malicious files in a dedicated, isolated virtual machine environment. 
SECURITY ALWAYS FIRST!

WALKTHROUGH:
Step 1 - download the file from CyberDefenders webiste and unzip it (by inputting the password provided).

Step 2 - Download Wireshark and Network Miner into your VM machine (if not already installed).

Let's start with our Investigation! 

Q1) Which IP address was used by the attacker during the initial access?
By analyzing the .pcap file in Wireshark we can see the 62.173.142.148 IP address tried and successfully connected to the server.
![pic1](https://github.com/user-attachments/assets/d6cb9908-177a-44b9-bdcb-34d905b366bf)

Q2) What is the name of the malicious file used for initial access?
In Wireshark, we will search for potential HTTP requests to identify any possible file transfers. Once we locate the relevant packets, we can follow the HTTP stream of the first packet. 

![pic2](https://github.com/user-attachments/assets/82592785-8c17-4783-ad99-7c9ac59d2551)

By doing so, we gain a more detailed view of the entire communication between the server and the client. This includes the requests, such as the "GET" request in this instance, and the subsequent response, "200 OK," indicating that the server is responding to the client regarding data or resources. In this case, the resource in question is the malicious file allegato_708.js.

![pic3](https://github.com/user-attachments/assets/be3331e3-6ade-48a3-8f61-49c982dfc572)

Q3) What is the SHA-256 hash of the malicious file used for initial access?
The .pcap file can then be imported into NetworkMiner. Navigate to Files > allegato_708.js and double-click the entry. The SHA256 hash will be displayed in the corresponding details pane

![pic4](https://github.com/user-attachments/assets/36c74788-7486-496a-bd3a-a303f9094af3)

Q4) Which process was used to execute the malicious file?
To find which process was used to execute the file we will need to head to VirusTotal and paste the hash to see the following details about the file (below)

![pic5](https://github.com/user-attachments/assets/6edf416d-4c60-451e-874b-9a559e77f601)

Since the file "allegato_708.js" is a malicious JavaScript file we can have a look at the MITRE framework and find that it employs techniques such as executing scripts (T1059.007) and querying process information (T1071.001). In our case we will have to look at execution files (.exe) within the registry actions to find that the answer is "wscript.exe".

![pic 6 - iniziale](https://github.com/user-attachments/assets/9374caf3-34bc-477b-9eed-00602c9a4258)

Q5) What is the file extension of the second malicious file utilized by the attacker?
Back at Wireshark. Taking the method employed in question number 2, we can see that another file has been utilized by the attacker and the extension of the file is .dll .

![pic6](https://github.com/user-attachments/assets/6e8d6b3b-4553-4af8-a8e8-0eb13adbb481)

Q6) What is the MD5 hash of the second malicious file?
We will follow the same steps as we did with the previous file using the NetworkMiner program. By analyzing it, we obtain the following SHA256 hash: [2597322a49a6252445ca4c8d713320b238113b3b8fd8a2d6fc1088a5934cee0e]. We will then proceed to VirusTotal for a more in-depth analysis.
Upon navigating to the details section, we can find the MD5 hash located at the very top.

![pic8](https://github.com/user-attachments/assets/c177a8f6-a69f-48bc-bd8b-1feae4e7b27c)

CONCLUSIONS:
This investigation successfully identified and analyzed a DanaBot infection within the provided network traffic capture (PCAP). Leveraging tools such as Wireshark, NetworkMiner, and VirusTotal, we were able to trace the attack from initial access to the deployment of a second-stage payload.

The analysis revealed the following key findings:

Initial Access: The attacker gained initial access via the IP address 62.173.142.148, which initiated a three-way handshake indicative of establishing a connection with the target machine.

Malicious JavaScript: The initial infection vector was the malicious JavaScript file allegato_708.js, which was delivered through an HTTP GET request. Analyzing the HTTP stream in Wireshark allowed us to reconstruct the download and identify the file.

SHA256 Hash: The SHA256 hash of the allegato_708.js file, obtained using NetworkMiner, served as a crucial indicator for further analysis.

Execution Process: The allegato_708.js file was executed using wscript.exe, a legitimate Windows scripting host. This highlights the attacker's use of Living-off-the-Land Binaries (LOLBins) to evade initial detection. Our finding aligns with the MITRE ATT&CK framework's techniques of T1059.007 (execution of scripts) and T1071.001 (querying process information).

Second-Stage Payload: A second malicious file with the extension .dll was identified, indicating the deployment of a secondary payload by the attacker. This is common behavior for DanaBot, which often downloads additional modules for extended functionality.

MD5 Hash: Analysis of the second-stage DLL file (using NetworkMiner and VirusTotal) allowed us to determine its MD5 hash, providing another critical IOC for threat hunting.

Through this exercise, we successfully reconstructed the attack chain, identified key artifacts, and gained a deeper understanding of the attacker's tactics, techniques, and procedures (TTPs). This knowledge can be used to improve network defenses, develop threat hunting strategies, and enhance incident response capabilities to better defend against similar attacks in the future. The use of multiple tools and threat intelligence platforms was essential in piecing together the complete picture of the DanaBot infection.

I'd like to thank CyberDefenders for creating such an engaging and realistic lab scenario. This challenge provided a fantastic opportunity to sharpen investigative skills, starting with minimal information and expanding into a thorough analysis. It’s always rewarding to connect the dots between artifacts, tools, and external research to uncover the full scope of a threat. In real-world scenarios, where speed and accuracy are critical, platforms like VirusTotal and packet analysis software like Wireshark proved to be invaluable for identifying and mitigating threats efficiently. Exercises like this are not just practice—they’re essential preparation for the challenges we face every day in cybersecurity.

I hope you found this walkthrough insightful as well! If you found this content helpful, please consider giving it a clap! Your feedback is invaluable and motivates me to continue supporting your journey in the cybersecurity community. Remember, cybersecurity is a team sport, and we’re all in this together! For more insights and updates on cybersecurity analysis, follow me on Substack! [https://substack.com/@atlasprotect?r=1f5xo4&utm_campaign=profile&utm_medium=profile-page]

