# InstallCore
Retrieval for InstallCore Malware Analysis 

## Commercial Antivirus Limitation

Technically, the modus operandi for the identification of malicious files and servers refers to consult in named blacklist databases. The VirusTotal platform issues the diagnoses regarding malignant characteristics related to files and web servers.

When it comes to suspicious files, VirusTotal issues the diagnostics provided by the world's leading commercial antivirus products. Regarding suspicious web servers, VirusTotal uses the database responsible for sensing virtual addresses with malicious practices.

VirusTotal has Application Programming Interface (APIs) that allow programmers to query the platform in an automated way and without the use of the graphical web interface. The proposed paper employs two of the APIs made available by VirusTotal. The first one is responsible for sending the investigated files to the platform server. The second API, in turn, makes commercial antivirus diagnostics available for files submitted to the platform by the first API.

Initially, the executable malwares are sent to the server belonging to the VirusTotal platform. After that, the executables are analyzed by the 79 commercial antiviruses linked to VirusTotal. Therefore, the antivirus provides its diagnostics for the executables submitted to the platform. VirusTotal allows the possibility of issuing three different types of diagnostics: malware, benign and omission.

Then, through the VirusTotal platform, the proposed paper investigates 79 commercial antiviruses with their respective results presented in Table 1. We used 9,405 malicious executables for 32-bit architecture. The goal of the work is to check the number of virtual pests cataloged by antivirus. The motivation is that the acquisition of new virtual plagues plays an important role in combating malicious applications. Therefore, the larger the database of malwares blacklisted, the better it tends to be the defense provided by the antivirus.

As for the first possibility of VirusTotal, the antivirus detects the malignity of the suspicious file. In the proposed experimental environment, all submitted executables are public domain malwares. Therefore, in the proposed study, the antivirus hits when it detects the malignity of the investigated executable. Malware detection indicates that the antivirus provides a robust service against cyber-intrusions. As larger the blacklist database, better tends to be the defense provided by the antivirus.

In the second possibility, the antivirus attests to the benignity of the investigated file. Therefore, in the proposed study, when the antivirus attests the benignity of the file, it is a case of a false negative – since all the samples are malicious. That is, the investigated executable is a malware; however, the antivirus attests to benignity in the wrong way.

In the third possibility, the antivirus does not emit opinion about the suspect executable. The omission indicates that the file investigated has never been evaluated by the antivirus neither it has the robustness to evaluate it in real time. The omission of the diagnosis by the antivirus points to its limitation on large-scale services.

In the third possibility, the antivirus does not emit opinion about the suspect executable. The omission indicates that the file investigated has never been evaluated by the antivirus neither it has the robustness to evaluate it in real time. The omission of the diagnosis by the antivirus points to its limitation on large-scale services.

Table 1 shows the results of the evaluated 79 antivirus products. Two of these antiviruses scored above 99%. Eight antiviruses were: ESET-NOD32,	NANO-Antivirus, Comodo, Avira, DrWeb, VBA32, Microsoft, and Cyren. Malware detection indicates that these antivirus programs provide a robust service against cyber-intrusions.

A major adversity in combating malicious applications is the fact that antivirus makers do not share their malware blacklists due to commercial disputes. Through Table 1 analyse, the proposed work points to an aggravating factor of this adversity: the same antivirus vendor does not even share its databases between its different antivirus programs. Note, for example, that McAfee and McAfee-GW-Edition antiviruses belong to the same company. Their blacklists, though robust, are not shared with each other. Therefore, the commercial strategies of the same company hinder the confrontation with malware. It complements that antivirus vendors are not necessarily concerned with avoiding cyber-invasions, but with optimizing their business income.

Malware detection ranged from 0% to 99.79%, depending on the antivirus being investigated. On average, the 79 antiviruses were able to detect 66.71% of the evaluated virtual pests, with a standard deviation of 36.18%. The high standard deviation indicates that the detection of malicious executables may suffer abrupt variations depending on the antivirus chosen. It is determined that the protection, against cybernetic invasions, is due to the choice of a robust antivirus with a large and updated blacklist.

As for the false negatives, TACHYON, Paloalto, Zoner, Kingsoft, Baidu, and Avast-Mobile antiviruses wrongly stated that malware was benign in more than 90% of cases. On average, antiviruses attested false negatives in 23.85% of the cases, with a standard deviation of 31.15%. Tackling the benignity of malware can lead to irrecoverable damage. A person or institution, for example, would rely on a particular malicious application when, in fact, it is malware.

On average, the antiviruses were missing in 9.43% of the cases, with a standard deviation of 26.36%. The omission of the diagnosis points to the limitation of these antiviruses that have limited blacklists for detection of malware in real time.

It is included as adversity, in the combat to malicious applications, the fact of the commercial antiviruses do not possess a pattern in the classification of the malwares as seen in Table 2. We choose 3 of 9,405 malwares samples in order to exemplify the miscellaneous classifications of commercial antiviruses. In this way, the time when manufacturers react to a new virtual plague is affected dramatically. As there is no a pattern, antiviruses give the names that they want, for example, a company can identify a malware as "Malware.1" and a second company identify it as "Malware12310". Therefore, the lack of a pattern, besides the no-sharing of information among the antivirus manufacturers, hinders the fast and effective detection of a malicious application.

###### Table 1 Results of 79 commercial antiviruses:

Antivirus | Deteccion (%) | False Negative (%) | Omission (%)
--------- | ------------- | ------------------ | -------------
ESET-NOD32	| 99.79% |	0.19% |	0.02% |  
NANO-Antivirus	| 99.69%	| 0.26%	| 0.05% |
Comodo	| 99.63% |	0.06%	| 0.31% |
Avira	| 99.61%	| 0.23%	| 0.16% |
DrWeb	| 99.56%	| 0.29%	| 0.15% |
VBA32	| 99.27%	| 0.54%	| 0.19% |
Microsoft	| 99.18%	| 0.23%	| 0.58% |
Cyren	| 99.13%	| 0.75%	| 0.12% |
SentinelOne	| 98.94%	| 1.01%	| 0.05% |
Invincea	| 98.5%	| 0.09%	| 1.41% |
Malwarebytes	| 98.28%	| 1.18%	| 0.54% |
CrowdStrike	| 98.17%	| 1.55%	| 0.28% |
Rising	| 98.11%	| 0.91%	| 0.98% |
Emsisoft	| 97.87%	| 1.46%	| 0.67% |
McAfee-GW-Edition	| 97.81%	| 1.02%	| 1.17% |
Fortinet	| 97.78%	| 2.19%	| 0.03% |
McAfee	| 97.64%	| 2.09%	| 0.27% |
AVG	| 97.58%	| 1.46%	| 0.97% |
GData	| 96.87%	| 2.81%	| 0.32% |
K7AntiVirus	| 96.65%	| 3.29%	| 0.06% |
K7GW	| 96.63%	| 3.34%	| 0.03% |
Cylance	| 96.56%	| 0.19%	| 3.25% |
FireEye	| 96.35%	| 3.22%	| 0.43% |
ClamAV	| 96.23%	| 2.39%	| 1.38% |
Yandex	| 96.23%	| 3.23%	| 0.54% |
Endgame	| 96.17%	| 1.56%	| 2.26% |
Trapmine	| 95.74%	| 1.97%	| 2.3% |
Sophos	| 95.53%	| 4.24%	| 0.22% |
F-Secure	| 95.34%	| 3.88%	| 0.78% |
Zillya	| 94.94%	| 4.51%	| 0.55% |
SUPERAntiSpyware	| 94.27%	| 5.72%	| 0.01% |
VIPRE	| 93.64%	| 2.04%	| 4.32% |
CAT-QuickHeal	| 93.18%	| 6.61%	| 0.2% |
Acronis	| 92.75%	| 7.25%	| 0% |
F-Prot	| 92.45%	| 4.98%	| 2.57% |
MAX	| 91.08%	| 8.7%	| 0.22% |
Avast	| 89.6%	| 7.97%	| 2.42% |
Webroot	| 87.99%	| 11.35%	| 0.67% |
Tencent	| 86.83%	| 13.07%	| 0.11% |
CMC	| 83.71%	| 16.26%	| 0.03% |
AhnLab-V3	| 83.19%	| 16.81%	| 0% |
APEX	| 83.03%	| 16.93%	| 0.04% |
Symantec	| 80.84%	| 1.98%	| 17.18% |
Ikarus	| 80.73%	| 16.75%	| 2.52% |
Qihoo-360	| 79.55%	| 20.32%	| 0.13% |
MaxSecure	| 74.46%	| 7.74%	| 17.8% |
TrendMicro-HouseCall	| 70.64%	| 29.3%	| 0.05% |
Sangfor	| 67.59%	| 3.93%	| 28.47% |
Lionic	| 64.86%	| 34%	| 1.14% |
Jiangmin	| 61.28%	| 38.63%	| 0.1% |
Cybereason	| 57.66%	| 38.65%	| 3.69% |
TrendMicro	| 53.15%	| 46.66%	| 0.19% |
TotalDefense	| 52.63%	| 40.67%	| 6.7% |
MicroWorld-eScan%	| 48.05%	| 51.95%	| 0% |
BitDefender	| 47.99%	| 51.93%	| 0.09% |
Arcabit	| 47.51%	| 52.47%	| 0.02% |
Ad-Aware	| 47.34%	| 52.65%	| 0.01% |
eGambit	| 45.54%	| 52.1%	| 2.36% |
Bkav	| 41.86%	| 54.24%	| 3.9% |
ViRobot	| 37.4%	| 62.58%	| 0.02% |
Alibaba	| 34.45%	| 65.52%	| 0.03% |
Panda	| 33.94%	| 66.04%	| 0.02% |
Kaspersky	| 30.98%	| 68.73%	| 0.29% |
ZoneAlarm	| 30.78%	| 69.09%	| 0.13% |
Antiy-AVL	| 27.83%	| 71.54%	| 0.64% |
ALYac	| 26.87%	| 68.4%	| 4.73% |
TACHYON	| 8.34%	| 91.46%	| 0.2% |
Paloalto	| 8.16%	| 91.74%	| 0.11% |
Cynet	| 2.5%	| 0.02%	| 97.48% |
BitDefenderTheta	| 1.84%	| 70.55%	| 27.61% |
Elastic	| 1.42%	| 0.16%	| 98.42% |
Gridinsoft	| 1.17%	| 0.23%	| 98.6% |
Zoner	| 0.93%	| 98.9%	| 0.17% |
Kingsoft	| 0.39%	| 99.61%	| 0% |
Baidu	| 0.05%	| 99.57%	| 0.37% |
TheHacker	| 0.01%	| 0%	| 99.99% |
Avast-Mobile	| 0%	| 98.33%	| 1.67% |
Trustlook	| 0%	| 0.12%	| 99.88% |
Babable	| 0%	| 0.05%	| 99.95% |

###### Table 2 Miscellaneous classifications of commercial antiviruses:

Antivírus | VirusShare_001627d61a1bde3478ca4965e738dc1e | VirusShare_075efef8c9ca2f675be296d5f56406fa | VirusShare_0dab86f850fd3dafc98d0f2b401377d5
--------- | ------------------------------------------- | ------------------------------------------- | --------------------------------------------



## Materials and Methods

This paper proposes a database aiming at the classification of 32-bit benign and malware executables. There are 9,405 malicious executables, and 3,135 other benign executables. Therefore, our dataset is suitable for learning with artificial intelligence, since both classes of executables have the same amount.

Virtual plagues were extracted from databases provided by enthusiastic study groups as VirusShare. As for benign executables, the acquisition came from benign applications repositories such as sourceforge, github and sysinternals. It should be noted that all benign executables were submitted to VirusTotal and all were its benign attested by the main commercial antivirus worldwide. The diagnostics, provided by VirusTotal, corresponding to the benign and malware executables are available in the virtual address of our database.

The purpose of the creation of the database is to give full possibility of the proposed methodology being replicated by third parties in future works. Therefore, the proposed article, by making its database freely available, enables transparency and impartiality to research, as well as demonstrating the veracity of the results achieved. Therefore, it is hoped that the methodology will serve as a basis for the creation of new scientific works.

## Executable Feature Extraction

The extraction of features of executables employs the process of disassembling. Then, the algorithm, referring to the executable, can be studied and later classified by the neural networks described in the next section. In total, 407 features of each executable are extracted, referring to the groups mentioned above. The pescanner tool are employed in order to extract the features of executables. Next, the groups of features extracted from the executables investigated are detailed.
######	Histogram of instructions, in assembly, referring to the mnemonic.
######	Number of subroutines invoking TLS (Transport Layer Security).
######	Number of subroutines responsible for exporting data (exports).  
######	APIs (Application Programming Interface) used by the executable.
######	Features related to clues that the computer has suffered fragmentation on its hard disk, as well as accumulated invalid boot attempts.  
######	Application execution mode. There are two options:
-	software with a graphical interface (GUI);
-	software running on the console.
######	Features related to the Operating System. Our digital forensics examines if the tested file tries to:
-	identify the current operating system user name;
-	access APIs in order to create and manage current OS user profiles;
-	detect the number of milliseconds since the system was initialized;
-	execute an operation in a specific file;
-	identify the version of the Windows Operating System in use;
-	monitor internal message traffic among system processes;
-	alter the Windows startup settings and contents (STARTUPINFO);  
-	allow applications to access functionality provided by shell of the operating system, as well as alter it; 
-	change the logon messages at Windows OS startup; 
-	change native applications linked to standard dialog boxes in order to open and save files, choosing color and font, among other customizations;
-	configure Windows Server licensing ; 
-	configure Windows Server 2003;
-	change the system's power settings;
-	open a process, service, or native library of the Operating System; 
-	exclude the context of certificates linked to the Operating System; 
-	copy an existing file to a new file; 
-	create, open, delete, or alter a file;
-	create and execute new process(s); 
-	create new directory(s); 
-	search for specific file(s);  
-	create a service object and add it to the control manager database for a certain service; 
-	encrypt data. It is a typical strategy of ransomwares which sequester the victim's data through cryptography. To decrypt the data, the invader asks the user for a monetary amount so that he victim can have all his data back;
-	access file systems, devices, processes, threads and error handling of the system;
-	change the sound and audio device properties of the system;
-	access graphical content information for monitors, printers, and other Windows OS output devices; 
-	use and/or monitor the USB port;
-	control a driver of a particular device; 
-	investigate if a disk drive is a removable, fixed, CD / DVD-ROM, RAM or network drive;
######	Features related to Windows Registry (Regedit). It is worth noting that the victim may not be free from malware infection even after its detection and elimination. The persistence of malefactions, even after malware exclusion, occurs due to the insertion of malicious entries (keys) in Regedit. Then, when the operating system boots, the cyber-attack restarts because of the malicious key invoking the vulnerability exploited by malware (eg: redirect Internet Explorer home page). Then, our antivirus audits if the suspicious application tries to:
-	detect the NetBIOS name of the local computer. This name is established at system startup, when the system reads it in the registry (Regedit);
-	terminate a key of a specific registry; 
-	create a key from in a specific registry. If the key already exists in Regedit, then it will be read; 
-	delete a key and its values in Regedit; 
-	enumerate and   open subkeys of a specific open registry. 
######	Features related to spywares such as keyloggers (capture of keyboard information in order to theft of passwords and logins) and screenloggers (screen shot of the victim). Our antivirus audits if the analyzed file tries to:
-	detect in which part of the victim's screen there was an update;
-	identify the screen update region by copying it to a particular region;
-	capture AVI movies and videos from web cameras and other video hardware; 
-	capture information on electronic voting, specifically from the company Optical Vote-Trakker;
-	copy an array of keyboard key states. Such strategy is typical of keyloggers
-	monitor user's Internet activity and private information;
-	collect online bank passwords and other confidential information and to send the data to invader creator;
-	access a computer from remote locations, stealing passwords, Internet banking and personal data; 
-	create a BHO (Browser Helper Object) which is executed automatically every time when the web browser is started. It fits to emphasize that BHOs are not impeded by personal firewalls because they are identified as part of the browser. In a distorted way, BHOs are often used by adware and spyware in order to record keyboard and mouse entries
-	locate passwords stored on a computer.
######	Features related to Anti-forensic Digital which are techniques of removal, occultation and subversion of evidences with the goal of reducing the consequences of the results of forensic analyzes. Our antivirus investigates if the file tries to:
-	Suspend its own execution until a certain timeout interval has elapsed. A typical malware strategy that maintains itself inactive until the end of commercial antivirus quarantine;
-	Disable the victim's defense mechanisms, including Firewall and Antivirus;
-	disable automatic Windows updates;
-	detect if the own file is being scanned by an debugger of the Operating System;   
-	retrieve information about the first and next process found in an Operating System snapshot. Such strategy is typical of malwares that aim to corrupt backups and restore points of the Operating System;
-	hide one file in another. This strategy is named, technically, steganography which aims to hide malware in a benign program in the Task Manager;
-	disguise its own name in the Task Manager;
-	make use of libraries associated with Hackers Encyclopedia 2002;
-	Create a ZeroAcess cyber-attack type through firmware updates of hardware devices (eg, hard drive controlled).
######	Features related to the creation of GUI (Graphical User Interface) of the suspicious program. Our antivirus audits if the suspect file tries to: 
-	create a GUI at runtime; 
-	use DirectX which allows multimedia applications to draw 2D graphics; 
-	create a module that contains bitmap compression and decompression routines used for Microsoft Video for Windows;
-	create 3D graphics related to utilitarian functions used by OpenGL; 
-	detect shapes through computer vision and digital image processing;
-	access functionalities in order to create and to manage screen windows and more basic controls such as buttons and scrollbars, receive mouse and keyboard input, and other functionalities associated with the Windows GUI. This includes widgets like status bars, progress bars, toolbars, and guides; 
######	Features related to the illicit forensic of the RAM (main memory) of the local system. Our antivirus investigates if the suspicious application tries to:
-	access information in specific regions of main memory;
-	read data from an area of memory occupied by a specific process;
-	write data to a memory area in a specific process;
-	reserve, confirm or alter the status of a page region in the virtual address space of a process.
######	Features related to network traffic. It is checked if the suspect file tries to:
-	query DNS servers;
-	send request to an HTTP server; 
-	monitor information of the headers of computer data packets associated with an HTTP request;
-	send an ICMP IPv4 echo request; 
-	send an SNMP request used to monitor LAN equipment;
-	terminate the Internet connection;
-	create an FTP or HTTP session at runtime; 
-	fragment a URL at runtime; 
-	query a server in order to determine the amount of traffic data available; 
-	identify the connection state of the local system in relation to the Internet; 
-	initialize the use of an application of the WinINet functions (Windows API for creating and using the application using the Internet); 
-	read data from network packets made from previous local system requests (typical behavior of sniffers); 
-	overwrite data in a local system network packet; 
-	manage local and remote network systems; 
-	create a network socket on the local system. In a conventional application, the server sends data to the client (s). In an opposite way, in malware, the victim sends the data (images, digits) to the server. Therefore, malware can create sockets on the local system waiting (listen) for a remote malicious computer to request a connection and, then, receive the victim's private information;
-	receive data of a socket. Typical strategy of backdoors when the victim starts receiving remote commands; 
-	send data to a socket. Typical strategies of spywares which, after capturing innermost information, they send them to a malicious remote computer; 
######	Features related to utility applications programs. Our created antivirus checks if the suspicious file tries to:
-	reproduce videos/audios through Windows Media Player; 
-	change the shortcut icon and Internet default settings exhibited in the Explorer toolbar address bar; 
-	alter the Wordpad configurations;
-	alter the configurations of sockets, specifically, managed by Internet Explorer; 
-	alter Outlook Express configurations and to access the victim’s  e-mail list; 
-	access information linked to the Microsof Office; 
-	alter the configurations of the Adobe System’s suite;
-	change the system's disk cleanup configurations; 
-	alter the settings of native digital electronic games and others linked to companies Tycoon and Electronic Arts;
-	change Google Inc updates settings; 
-	use Visual Basic. Such strategy is typical of macro viruses that are intended to infect applications that support macro language such as web browsers, Microsoft Office, and Adobe Systems.
-	alter the access settings to Wikipedia.
