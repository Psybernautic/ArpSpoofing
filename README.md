# ArpSpoofing
ARP Spoofing Detection and Simulation with Python: Learn how to detect and defend against one of the most common attacks on local networks.


# The Art of Deception

### Simulating ARP Spoofing Attacks and How to Catch Them




## Introduction

### What is ARP spoofing and Why is it Dangerous?


First, it's important to understand what ARP Spoofing is and why it's a concern. ARP (Address Resolution Protocol) is a protocol used by devices on a network to map their IP addresses to physical MAC addresses. ARP Spoofing is a type of attack where an attacker sends fake ARP messages to associate their MAC address with the IP address of another device on the network. This allows the attacker to intercept and modify traffic between the targeted devices, potentially leading to theft of sensitive information or other malicious activity.

Unfortunately, ARP Spoofing is a relatively easy attack to conduct, and it can be difficult to detect. This is where our Python program comes in - it automates the process of detecting potential ARP Spoofing attacks on a network. By using our program, you can quickly and easily identify any suspicious activity on your network and take appropriate action to protect your devices and data.

In this guide, we'll walk you through the installation and usage of our Python program, as well as provide tips for interpreting and acting on the results. Even if you're new to network security or Python programming, this guide is designed to be accessible and user-friendly, so you can start protecting your network right away.




Please note that the instructions in this guide are intended for educational purposes only. Any attempt to use these techniques for illegal or malicious purposes is strictly prohibited. The author of this guide does not condone or encourage any illegal or unethical activity. Use of these techniques should be limited to lab environments with appropriate permissions and safeguards in place.



## Understanding the ARP Protocol

### How ARP Spoofing Works


ARP Spoofing works by exploiting the way that devices on a network use the ARP protocol to map IP addresses to physical MAC addresses. When a device wants to communicate with another device on the network, it sends an ARP request asking for the MAC address of the device with the desired IP address. The device with that IP address responds with its MAC address, allowing the requesting device to send data to the correct destination.

In an ARP Spoofing attack, an attacker sends fake ARP messages to associate their MAC address with the IP address of another device on the network. For example, the attacker might send an ARP message to a victim device, falsely claiming to be the router and providing the attacker's MAC address as the correct address for the router's IP address. The victim device will then send all of its network traffic to the attacker's MAC address, thinking it's sending it to the router.

Once the attacker has intercepted the victim device's network traffic, they can use various techniques to steal information or modify the traffic for malicious purposes. This can include intercepting login credentials or financial information, injecting malware or spyware into the victim's device, or simply disrupting network communications.

One of the reasons ARP Spoofing is so effective is that it can be difficult to detect. The victim device may not even realize that its traffic is being intercepted, as everything may appear to be functioning normally from the device's perspective. However, with the right tools and techniques, it is possible to detect and prevent ARP Spoofing attacks, which is where our Python program comes in.


## Using Python to Detect ARP Spoofing

### Overview of the ARP Spoofing Detection Program


Python is a popular programming language that is widely used in the field of cyber security. In this guide, we will introduce you to a Python program that can be used to detect ARP Spoofing on a network. 

Our Python program is designed to detect ARP Spoofing attacks on your network. ARP Spoofing is a type of attack where an attacker sends fake ARP messages to intercept network traffic and steal information, such as login credentials or financial data. The program works by creating a table of MAC and IP address pairs for devices on your network, which it uses to detect potential ARP Spoofing attacks.

Each time the program runs, it scans the network and adds any new MAC/IP pairs to the table. It then compares the MAC and IP address pairs in the table to the ones it's currently detecting on the network. If a pair in the table matches the pair being detected, it assumes that no ARP Spoofing is taking place. However, if the program detects a pair that doesn't match any in the table, it raises an alarm that a potential ARP Spoofing attack may be taking place.

In addition to detecting ARP Spoofing attacks, the program helps you keep track of the devices on your network by maintaining a running record of MAC and IP address pairs. This makes it easier to spot suspicious activity and maintain network security over time.

By using our Python program, you can protect your network from potential ARP Spoofing attacks and keep your data safe. Our program is easy to use and can be customized to meet your specific needs.



## Code Walkthrough

### Blue Team
This Python program is a tool that can be used by Blue Teams in cybersecurity to detect and mitigate ARP Spoofing attacks on their network. ARP Spoofing is a common technique used by attackers to intercept network traffic and steal sensitive information, so being able to detect and respond to these attacks is crucial for maintaining the security of a network. By using this program, Blue Teams can proactively monitor their network and identify potential security threats, allowing them to take swift action to protect their assets and prevent data breaches.

## Blue Team Code Breakdown


This Python code uses the Scapy library to sniff network traffic and detect potential ARP Spoofing attacks. When a packet is sniffed, the processPacket() function is called to analyze the packet.

The processPacket() function extracts the source IP and MAC addresses from the ARP packet and Ethernet packet, respectively. It then checks if the source MAC address is already in the IP_MAC_Map dictionary, which maps MAC addresses to IP addresses. If the source MAC address is found in the dictionary, the function checks if the corresponding IP address matches the one from the current packet. If it doesn't match, the function raises an alarm that a potential ARP Spoofing attack may be taking place.

If the source MAC address is not found in the dictionary, the function adds the MAC/IP pair to the dictionary for future reference.

The sniff() function is used to capture network traffic and calls the processPacket() function for each packet it captures. The count=0 argument specifies that the function should run indefinitely until interrupted, while the filter="arp" argument tells the function to only capture ARP packets. The store=0 argument specifies that packets should not be stored in memory, which helps prevent memory overflow.

Overall, this Python code provides a basic framework for detecting ARP Spoofing attacks on a network using Scapy. It can be customized and extended to meet specific network security needs.




## Code Walkthrough

### Red Team
This Python code is related to the red team in cybersecurity as it can be used for performing a man-in-the-middle attack, which is a common technique used by attackers to intercept and eavesdrop on network traffic. In a typical man-in-the-middle attack scenario, the attacker intercepts and alters the communication between two parties, such as a client and a server, to gain access to sensitive information. By using this code, an attacker can send spoofed ARP packets to the victim and the router, which allows the attacker to intercept and manipulate the network traffic between them. The code allows an attacker to remain undetected by constantly sending the spoofed ARP packets until the attack is terminated or until the victim's ARP cache is poisoned.

## Red Team Code Breakdown


This Python code performs an ARP Spoofing attack on a victim machine and a router in a network. The program first imports the necessary libraries, scapy and sys, before defining two functions, arp_spoof() and arp_restore(). The arp_spoof() function creates an ARP packet with the destination IP address and MAC address of the victim machine and the source IP address of the router, while the arp_restore() function restores the ARP tables of both the router and the victim machine after the attack is complete.

The main() function uses the sys.argv method to obtain the IP addresses of the victim and the router, and uses the getmacbyip() method to get their respective MAC addresses. The program then initiates an infinite loop where it continuously sends spoofed ARP packets to the victim and router IP addresses. If a keyboard interrupt is detected, the program will restore the ARP tables of the victim and router using the arp_restore() function.

This code can be used maliciously by attackers to intercept network traffic and steal sensitive information. However, it can also be used by Blue Teams in cybersecurity to test their network defenses and identify vulnerabilities. By understanding how ARP Spoofing attacks work, Blue Teams can take proactive measures to prevent such attacks from being successful.



## Running The Application

To analyze ARP traffic and identify spoofing attacks, you can use the ARP Spoofing Detection Program and configure the detection parameters. The program monitors the network traffic for patterns that indicate a spoofing attack and will notify you if one is detected. Additionally, it provides information about the attack such as the IP and MAC addresses of the devices involved. By running this program, you can better protect your network from malicious ARP spoofing attacks.

To simulate an ARP spoofing attack, we need a target machine in the lab environment that will act as the victim of the attack in a man-in-the-middle scenario. In our example, we are using a Kali Linux machine, a Metasploitable 2 machine, and a pfSense router. The Metasploitable 2 machine will serve as our target, which we will attempt to attack.

## Step By Step Process

The following commands will execute a man-in-the-middle attack and trigger the ARP spoofing detection program. Open a new terminal and follow along.

### Analyze machines connected in the local network and identify the router and target machine. 

Sudo netdiscover

Netdiscover has detected two IP addresses in the image below. We need to identify which IP belongs to the router and which one is our target. In this case, the lowest IP address belongs to the router. The second IP address found belongs to our victims machine.



We can now start the ARP spoofing detection program, which will scan the network for ARP packets and alert us to any suspicious activity. It's important to note that this program functions similarly to an IDS (Intrusion Detection System), as it will scan packets moving across the network, but will not take any action to stop them, even if they are found to be malicious.

### Navigate to the directory containing the Python code responsible for detecting spoofed ARP packets. To run the program, enter the following command:

Sudo python3 arpDetector.py






### Now that we have our ARP spoofing IDS running, we can simulate an ARP spoofing attack by sending spoofed ARP packets and observing if any alerts are triggered by the IDS.

Previously, our netdiscover scan helped us identify the IP addresses of the router and the victim's machine on the network. We will be using this information along with the ARP spoofing code to simulate a man-in-the-middle attack. For this example, we have determined the following:

Router IP Address:  	192.168.1.1
Victim IP Address:	192.168.1.100

### Start a new terminal and traverse to the folder containing the source code. Initiate the attack by entering the following command:

sudo python3 arpSpoof.py 192.168.1.100 192.168.1.1



The program continuously sends spoofed ARP packets in order to intercept the data being sent across the two IP addresses. 

You can stop the attack at any time by pressing ctrl + c

Terminating the attack will instruct the program to restore the ARP table on the victim's machine in order to avoid detection. 








Upon the ARP tables being restored on the victim's machine, our host machine that is running the ARP spoofing IDS will detect changes in the network that it seemed suspicious. An alert will be sent to the host running the IDS.



The program performed as intended, detecting a man-in-the-middle attack on the network. The output showed that an IP address other than the known router and victim IP addresses was claiming to be both of those devices. This indicates that an ARP spoofing attack was not only carried out, but also successful.









## Responding to Detected ARP Spoofing

### Best Practices for Network Security


If the ARP Spoofing Detection Program detects a spoofing attack on your network, it is important to respond quickly and effectively to minimize the impact of the attack. In this section, we will provide you with best practices for responding to detected ARP Spoofing attacks, including how to isolate the affected devices, block the attacker's traffic, and improve the overall security of your network.

In the presence of an ARP spoofing attack, one way to isolate the affected devices and block the attacker's traffic is to implement network segmentation. This involves dividing the network into smaller subnetworks, each with its own router and firewall. By doing this, traffic can be controlled more effectively, and it becomes easier to detect and isolate the affected devices. Additionally, network administrators can use tools like intrusion detection systems (IDS) and intrusion prevention systems (IPS) to monitor network traffic and identify and block malicious traffic originating from the attacker's machine. It is also recommended to regularly update the ARP cache table to ensure that it only contains valid entries, and to implement encryption protocols such as HTTPS to protect sensitive data.


