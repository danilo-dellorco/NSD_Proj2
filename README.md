# Second Project for Network & System Defense 2022/2023

In this project, you are expected to create a virtualized environment to test binaries for the presence of malware. In particular, you have to setup multiple virtual machines or containers in Site 2, each hosting a different AV of your choice. 

A central node (in Site 3) will allow dropping an executable and distributing it to the various testing nodes. The testing nodes will scan/run the executables and deliver results to the central node, which will build a report to the user, showing what threats (if any) were discovered in the binary. 

Given the criticality of this infrastructure, certain precautions must be taken: 
1. Runner nodes must be subject to snapshots so that they can be restarted in a 'clean' state each time a new scan has to be started. 
2. To prevent the exfiltration of threats on the network, nodes must be protected by a firewall implemented in CE-A2. The firewall must permit the bidirectional end-to-end communication between the central node and the AVs, and deny all the rest. 

In the central node, setup an external internet connection through a VirtualBox NAT interface. Except for LAN-A2, the rest of the network configuration is the same as in Project 1, including the hub-and-spoke BGP/MPLS VPN connecting the three customer sites.
