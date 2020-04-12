# Memeories
**Author: bolzzy**

**Difficulty: easy**

**Category: forensics**

Oh noes, someone broke into the ship's computer systems and stole some very important files!
Our team managed to collect pcap and memory from the host. Can you figure out what secrets was stolen?

* [Download PCAP](uploads/capture.pcap.7z).
* [Download Mem dump](https://storage.googleapis.com/tghack-public/dreiuwohy894302794w3etruioewidgfo/host.vmem.7z).

```
52682851bad773076567911acc2bbfc4  capture.pcap.7z
f594ad3fe2038758d80ee634550b3593  host.vmem.7z
```

---

## Solution:

We start by downloading and extracting the two 7zip compressed files using the method of choise left to the user, in my example:
```
$ 7z x capture.pcap.7z 
$ 7z x host.vmem.7z
```

To make use of the information we got in the task description, we start by looking at the PCAP file in wireshark.
There is not a lot of packets in this capture and just by browsing we see some SMB activity parsed nicely by wireshark. We could apply a ```smb2``` filter to just focus on the smb packets, but in this task we already see the relevant info we where after in the ```Info``` column containing info about a transfer of a file named ```upload.7z```.

As this transfer was done using smb2 we can use a very nice feature in Wireshark: Carving transfered files in supported protocols.
We do this by selecting in the wireshark menu: ```File->Export Objects->SMB```
In the next menu, select the file you want to save, in this case ```\upload.7z``` and press save.

Unfortunatly the carved file is a password protected 7z archive, yet.

Now onto part two: Looking at the memory dump ```host.vmem```.
Looking at the filename, we can estimate that this is a vmware memory file that can be analyzed using a framework such as Volatility, or just straight with unix tools or hex editors.

To solve this task, we do not actually need to use volatility at all, but I will show some simple usage here that can be skipped if wanted:

Here I'm using the public beta version of the new Volatility 3 that has some amazing new features and fantastic performance improvements.
Volatility 3 can be found [here](https://github.com/volatilityfoundation/volatility3).

To start out exploring the processes we start by using the PsTree plugin:
```
python volatility3/vol.py -f host.vmem windows.pstree
..
[Trunkated some lines here]
..
*** 5208	804	browser_broker	0xbc8f116e2080	10	-	1	False	2019-10-20 21:12:03.000000 	N/A
**** 8240	5208	wandows (2).ex	0xbc8f116e2080	4	-	1	True	2019-10-20 21:18:15.000000 	N/A
***** 8540	8240	cmd.exe	0xbc8f116e2080	1	-	1	True	2019-10-20 21:18:47.000000 	N/A
****** 8596	8540	powershell.exe	0xbc8f116e2080	12	-	1	True	2019-10-20 21:18:49.000000 	N/A
****** 8548	8540	conhost.exe	0xbc8f116e2080	3	-	1	False	2019-10-20 21:18:47.000000 	N/A
*** 7000	804	GameBarPresenc	0xbc8f116e2080	4	-	1	False	2019-10-20 21:14:52.000000 	N/A
*** 5596	804	RuntimeBroker.	0xbc8f116e2080	6	-	1	False	2019-10-20 21:12:07.000000 	N/A
*** 6236	804	MicrosoftEdgeC	0xbc8f116e2080	14	-	1	False	2019-10-20 21:14:41.000000 	N/A
*** 7004	804	SkypeApp.exe	0xbc8f116e2080	26	-	1	False	2019-10-20 21:15:27.000000 	N/A
*** 6628	804	Calculator.exe	0xbc8f116e2080	24	-	1	False	2019-10-20 21:14:57.000000 	N/A
*** 4076	804	WmiPrvSE.exe	0xbc8f116e2080	10	-	0	False	2019-10-20 21:11:34.000000 	N/A
*** 6380	804	HxOutlook.exe	0xbc8f116e2080	30	-	1	False	2019-10-20 21:14:31.000000 	N/A
*** 6132	804	RuntimeBroker.	0xbc8f116e2080	6	-	1	False	2019-10-20 21:12:06.000000 	N/A
*** 4084	804	RuntimeBroker.	0xbc8f116e2080	7	-	1	False	2019-10-20 21:14:32.000000 	N/A
*** 3704	804	SkypeHost.exe	0xbc8f116e2080	36	-	1	False	2019-10-20 21:12:02.000000 	N/A
*** 3580	804	WinStore.App.e	0xbc8f116e2080	26	-	1	False	2019-10-20 21:14:32.000000 	N/A
** 1448	608	svchost.exe	0xbc8f116e2080	7	-	0	False	2019-10-20 21:11:12.000000 	N/A
** 1320	608	MsMpEng.exe	0xbc8f116e2080	20	-	0	False	2019-10-20 21:11:13.000000 	N/A
** 2600	608	cygrunsrv.exe	0xbc8f116e2080	6	-	0	False	2019-10-20 21:11:14.000000 	N/A
*** 3572	2600	cygrunsrv.exe	0xbc8f116e2080	0	-	0	False	2019-10-20 21:11:19.000000 	2019-10-20 21:11:19.000000 
**** 3624	3572	sshd.exe	0xbc8f116e2080	5	-	0	False	2019-10-20 21:11:19.000000 	N/A
**** 3596	3572	conhost.exe	0xbc8f116e2080	5	-	0	False	2019-10-20 21:11:19.000000 	N/A
** 1716	608	spoolsv.exe	0xbc8f116e2080	13	-	0	False	2019-10-20 21:11:12.000000 	N/A
** 1468	608	svchost.exe	0xbc8f116e2080	9	-	0	False	2019-10-20 21:11:12.000000 	N/A
** 1596	608	svchost.exe	0xbc8f116e2080	5	-	0	False	2019-10-20 21:11:12.000000 	N/A
** 3904	608	svchost.exe	0xbc8f116e2080	25	-	1	False	2019-10-20 21:11:58.000000 	N/A
** 1604	608	svchost.exe	0xbc8f116e2080	13	-	0	False	2019-10-20 21:11:12.000000 	N/A
** 1228	608	svchost.exe	0xbc8f116e2080	32	-	0	False	2019-10-20 21:11:12.000000 	N/A
** 340	608	svchost.exe	0xbc8f116e2080	91	-	0	False	2019-10-20 21:11:11.000000 	N/A
*** 3840	340	sihost.exe	0xbc8f116e2080	16	-	1	False	2019-10-20 21:11:58.000000 	N/A
*** 3660	340	taskhostw.exe	0xbc8f116e2080	11	-	1	False	2019-10-20 21:11:58.000000 	N/A
** 2260	608	svchost.exe	0xbc8f116e2080	15	-	0	False	2019-10-20 21:11:13.000000 	N/A
** 2772	608	svchost.exe	0xbc8f116e2080	5	-	0	False	2019-10-20 21:11:15.000000 	N/A
** 348	608	svchost.exe	0xbc8f116e2080	26	-	0	False	2019-10-20 21:11:11.000000 	N/A
** 864	608	svchost.exe	0xbc8f116e2080	19	-	0	False	2019-10-20 21:11:11.000000 	N/A
** 2020	608	svchost.exe	0xbc8f116e2080	14	-	0	False	2019-10-20 21:11:13.000000 	N/A
** 5220	608	svchost.exe	0xbc8f116e2080	7	-	0	False	2019-10-20 21:12:03.000000 	N/A
*** 5228	5220	Windows.WARP.J	0xbc8f116e2080	4	-	0	False	2019-10-20 21:14:34.000000 	N/A
*** 5332	5220	Windows.WARP.J	0xbc8f116e2080	4	-	0	False	2019-10-20 21:12:03.000000 	N/A
*** 4584	5220	Windows.WARP.J	0xbc8f116e2080	4	-	0	False	2019-10-20 21:17:50.000000 	N/A
** 1384	608	SecurityHealth	0xbc8f116e2080	20	-	0	False	2019-10-20 21:11:13.000000 	N/A
** 3304	608	svchost.exe	0xbc8f116e2080	7	-	0	False	2019-10-20 21:14:34.000000 	N/A
** 2040	608	vmtoolsd.exe	0xbc8f116e2080	12	-	0	False	2019-10-20 21:11:13.000000 	N/A
*** 8384	2040	cmd.exe	0xbc8f116e2080	0	-	0	False	2019-10-20 21:21:37.000000 	2019-10-20 21:21:38.000000 
**** 8452	8384	conhost.exe	0xbc8f116e2080	0	-	0	False	2019-10-20 21:21:37.000000 	2019-10-20 21:21:38.000000 
** 1144	608	svchost.exe	0xbc8f116e2080	28	-	0	False	2019-10-20 21:11:12.000000 	N/A
* 640	504	lsass.exe	0xbc8f116e2080	9	-	0	False	2019-10-20 21:11:11.000000 	N/A
* 720	504	fontdrvhost.ex	0xbc8f116e2080	6	-	0	False	2019-10-20 21:11:11.000000 	N/A
520	496	csrss.exe	0xbc8f116e2080	12	-	1	False	2019-10-20 21:11:11.000000 	N/A
596	496	winlogon.exe	0xbc8f116e2080	6	-	1	False	2019-10-20 21:11:11.000000 	N/A
* 728	596	fontdrvhost.ex	0xbc8f116e2080	6	-	1	False	2019-10-20 21:11:11.000000 	N/A
* 3336	596	userinit.exe	0xbc8f116e2080	0	-	1	False	2019-10-20 21:11:59.000000 	2019-10-20 21:12:20.000000 
** 2400	3336	explorer.exe	0xbc8f116e2080	99	-	1	False	2019-10-20 21:11:59.000000 	N/A
*** 6944	2400	OfficeHubWin32	0xbc8f116e2080	18	-	1	False	2019-10-20 21:15:12.000000 	N/A
*** 5924	2400	vmtoolsd.exe	0xbc8f116e2080	9	-	1	False	2019-10-20 21:12:15.000000 	N/A
*** 5864	2400	vm3dservice.ex	0xbc8f116e2080	5	-	1	False	2019-10-20 21:12:14.000000 	N/A
*** 1964	2400	OneDrive.exe	0xbc8f116e2080	21	-	1	True	2019-10-20 21:12:16.000000 	N/A
*** 5036	2400	MSASCuiL.exe	0xbc8f116e2080	4	-	1	False	2019-10-20 21:12:14.000000 	N/A
*** 3436	2400	notepad.exe	0xbc8f116e2080	10	-	1	False	2019-10-20 21:17:05.000000 	N/A
*** 7060	2400	soffice.exe	0xbc8f116e2080	2	-	1	False	2019-10-20 21:14:08.000000 	N/A
**** 2584	7060	soffice.bin	0xbc8f116e2080	11	-	1	False	2019-10-20 21:14:08.000000 	N/A
* 972	596	dwm.exe	0xbc8f116e2080	14	-	1	False	2019-10-20 21:11:11.000000 	N/A
```

Just by looking at the process tree we get a pretty nice overview of what processes was run on this host and we can already see a very suspicious process ```wandows (2).ex``` that was launched from a browser and has a commandline process that launched powershell as children processes.
However, we do not see any traces of 7zip usage here.
To follow up this we can use other plugins like ```windows.psscan``` that can find processes that hides itself and terminated processes or ```windows.cmdline``` to get cmd history. Unfortunatly, this did not give us any hints on the password of the archive. In general its a good thumb rule to never 100% trust the tool, so we continue on using a simpler, yet effective method: ```strings```.


As we already know the name of the file was was exfiltrated ```upload.7z``` it is a good staring point to search for using string and grep:
```
$ strings host.vmem | grep 'upload.7z'
PS C:\Users\IEUser>  L:\upload.7z
Destination L:\upload.7z
cp C:\IEUser\jeff.7z L:\upload.7z
Destination L:\upload.7z
4cp C:\IEUser\jeff.7z L:\upload.7z
Destination L:\upload.7z
```

There we go! Here we see a copy of the file from ```jeff.7z``` to ```upload.7z```. Now lets seach for ```jeff.7z```:

```
$ strings host.vmem | grep 'jeff.7z'                                                                                                20s
Path C:\IEUser\jeff.7z 
4C:\Users\IEUser\7za.exe a C:\IEUser\jeff.7z "C:\Users\IEUser\Desktop\very important documents" -phekktheplanet
Creating archive: C:\IEUser\jeff.7z
cp C:\IEUser\jeff.7z L:\upload.7z
4cp C:\IEUser\jeff.7z L:\upload.7z
Path C:\IEUser\jeff.7z 
```

Bingo! Here we see the password for the archive that was uploaded: ```hekktheplanet```.
We then extact the contents of ```upload.7z```:
```
7z x upload.7z -phekktheplanet
```

In the folder we just unpacked we got 3 files:
```
3amqhd.jpg  
3amr2d.jpg
SuperSensitiveDocumentOnlyForInternalViewing_Final_2019_v3_final1_versioncontrol_done_1.odt
```

Opening the ```SuperSensitiveDocumentOnlyForInternalViewing_Final_2019_v3_final1_versioncontrol_done_1.odt``` in libreoffice we scroll to the bottom and see the end of the flag. To see the whole flag we can move the picture containing the flag.

```
TG20{stealing_yo_flagz}
```
