# Second Project for Network & System Defense 2022/2023

In this project, you are expected to create a virtualized environment to test binaries for the presence of malware. In particular, you have to setup multiple virtual machines or containers in Site 2, each hosting a different AV of your choice. 

A central node (in Site 3) will allow dropping an executable and distributing it to the various testing nodes. The testing nodes will scan/run the executables and deliver results to the central node, which will build a report to the user, showing what threats (if any) were discovered in the binary. 

Given the criticality of this infrastructure, certain precautions must be taken: 
1. Runner nodes must be subject to snapshots so that they can be restarted in a 'clean' state each time a new scan has to be started. 
2. To prevent the exfiltration of threats on the network, nodes must be protected by a firewall implemented in CE-A2. The firewall must permit the bidirectional end-to-end communication between the central node and the AVs, and deny all the rest. 

In the central node, setup an external internet connection through a VirtualBox NAT interface. Except for LAN-A2, the rest of the network configuration is the same as in Project 1, including the hub-and-spoke BGP/MPLS VPN connecting the three customer sites.

# Project Folder Structure
 
 - **```gns-proj2```**
   - Contains the GNS3 Project
  
 - **```docker```**
   - Mantains the Dockerfiles and resources of all the containers images used in the projects
   - Every subfolder contains the `.sh` scripts and all the files to configure the specific containers
     - ```clamav | jmdav | rkhav ```
       - ```av```: keeps all the scripts and files used by the av engine
       - ```./start.sh```: start command used in `docker run`, to configure the container interfaces and start the antivirus service in background.
     - ```openvpn```
       - ```config```: keeps all the file used to configure openvpn
       - ```script```: keeps the scripts used to configure the specific hosts
     - ```simple-ubuntu```: Dockerfile to build an ubuntu container with some useful tools pre-installed.

 - **```VMs```**
   - Mantains all the files used in the virtual machines for configuration and services.
   - Every subfolder contains the `.sh` scripts and all the files to configure the specific containers
     - ```central-node```
       - ```av```: keeps files and folders to execute the remote analysis
       - ```./start.sh```: script to configure interfaces and start the listening service of the antivirus framework. 
       - ```./downloader.sh```: script to download a malware from the [Our Malware Sample Repository](https://github.com/danilo-dellorco/malwares-sample)
       - ```Scaricati```: default folder scanned by the antivirus, and in witch `downloader.sh` downloads the malware.

     - ```web-server```
       - ```details```: keeps files and folders to execute the remote analysis
       - ```scans```: script to configure interfaces and start the listening service of the antivirus framework. 
       - ```hostA1.sh```: script to download a malware from the [Our Malware Sample Repository](https://github.com/danilo-dellorco/malwares-sample)
       - ```hostA2.sh```: default folder scanned by the antivirus, and in witch `downloader.sh` downloads the malware.  
       - ```index.html```: default folder scanned by the antivirus, and in witch `downloader.sh` downloads the malware.  
       - ```server.py```: default folder scanned by the antivirus, and in witch `downloader.sh` downloads the malware.  
       - ```utils.py```: default folder scanned by the antivirus, and in witch `downloader.sh` downloads the malware.  