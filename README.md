# quick-threat-hunting
Quick scripts and one liners to look for malicious processes, persistence, and obfuscation techniques

# Windows OS Quickstart
1. Spawn an **Administrator** PowerShell terminal.
2. Run this PowerShell one-liner to download and execute the script.
   
   `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Ssl3; Invoke-WebRequest "https://raw.githubusercontent.com/brandondudley1775/quick-threat-hunting/main/os_windows.ps1" -OutFile .\os_windows.ps1 -UseBasicParsing; Set-ExecutionPolicy RemoteSigned -Force; Unblock-File .\os_windows.ps1; .\os_windows.ps1`

# Linux OS Quickstart
1. Spawn a root shell, user will work if root is unavailable.  Try these commands:

`sudo su`

or

`sudo su - root`

or

`sudo find /home -exec /bin/bash \;`

2. Run the command to retrieve and run the script, there are two possible commands to choose from to account for missing binaries/permissions:

`wget https://raw.githubusercontent.com/brandondudley1775/quick-threat-hunting/main/os_linux.py; python3 os_linux.py`

or

`curl https://raw.githubusercontent.com/brandondudley1775/quick-threat-hunting/main/os_linux.py > os_linux.py; python3 os_linux.py`
# Linux Python Portscan (top 1000 ports)
This one-liner will scan the top 1,000 ports as they appear in nmap.
`python -c "import socket; target_ip = raw_input('Enter the target IP address >>>'); print([port for port in [1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,2920,2967,2968,2998,3000,3001,3003,3005,3006,3007,3011,3013,3017,3030,3031,3052,3071,3077,3128,3168,3211,3221,3260,3261,3268,3269,3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,3370,3371,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,4005,4006,4045,4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,4550,4567,4662,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,5190,5200,5214,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,5800,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,6004,6005,6006,6007,6009,6025,6059,6100,6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565,6566,6567,6580,6646,6666,6667,6668,6669,6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,7103,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,9000,9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,9100,9101,9102,9103,9110,9111,9200,9207,9220,9290,9415,9418,9485,9500,9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,9898,9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11967,12000,12174,12265,12345,13456,13722,13782,13783,14000,14238,14441,14442,15000,15002,15003,15004,15660,15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,27000,27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,32785,33354,33899,34571,34572,34573,35500,38292,40193,40911,41511,42510,44176,44442,44443,44501,45100,48080,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,49175,49176,49400,49999,50000,50001,50002,50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55555,55600,56737,56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389] if 0 == socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect_ex((target_ip,port))])"`

# Linux Python Portscan (all ports)
This python one-liner will scan all 65,535 ports on a specified IP.
`python -c "import socket; target_ip = raw_input('Enter the target IP address >>>'); print([port for port in range(0, 65535) if 0 == socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect_ex((target_ip,port))])"`

# Linux Python Host Discovery and Portscan on all networks on all interfaces
`echo cHl0aG9uIDw8IEVORAppbXBvcnQgb3MsIHNvY2tldAoKY29tbW9uX3BvcnRzID0gWzIwLCAyMSwgMjIsIDIzLCAyNSwgNTMsIDY5LCA4MCwgODgsIDMzODldCgpkZWYgcG9ydF9zY2FuX2NvbW1vbl9wb3J0cyhpcCk6CiAgICBvcGVuX3BvcnRzID0gW10KICAgIGZvciBwb3J0IGluIGNvbW1vbl9wb3J0czoKICAgICAgICBzID0gc29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCwgc29ja2V0LlNPQ0tfU1RSRUFNKQogICAgICAgIHMuc2V0dGltZW91dCgwLjIpCgogICAgICAgIHRyeToKICAgICAgICAgICAgY29uID0gcy5jb25uZWN0KChpcCxwb3J0KSkKICAgICAgICAgICAgb3Blbl9wb3J0cy5hcHBlbmQocG9ydCkKICAgICAgICAgICAgY29uLmNsb3NlKCkKICAgICAgICBleGNlcHQ6CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICByZXR1cm4gb3Blbl9wb3J0cwoKZGVmIGV4cGFuZF9jaWRyKG5ldCk6CiAgICB0cnk6CiAgICAgICAgY2lkciA9IGludChuZXQuc3BsaXQoIi8iKVstMV0pCiAgICBleGNlcHQ6CiAgICAgICAgcmV0dXJuIFtdCiAgICB0cnk6CiAgICAgICAgb2N0ZXRzID0gW2ludChvKSBmb3IgbyBpbiBuZXQuc3BsaXQoIi8iKVswXS5zcGxpdCgiLiIpXQogICAgZXhjZXB0OgogICAgICAgIHJldHVybiBbXQoKICAgICMgZ2V0IHRoZSBuZXR3b3JrIGJpdHM6ICcwYjExJwogICAgYmluX2lwID0gJycKICAgIGZvciBvIGluIG9jdGV0czoKICAgICAgICBiaW5fc3RyID0gYmluKG8pWzI6XQogICAgICAgIHdoaWxlIGxlbihiaW5fc3RyKSA8IDg6CiAgICAgICAgICAgIGJpbl9zdHIgPSAnMCcrYmluX3N0cgoKICAgICAgICBiaW5faXAgPSBiaW5faXAgKyBiaW5fc3RyCgogICAgc3RhcnQgPSBiaW5faXBbOmNpZHJdCiAgICBzdG9wID0gYmluX2lwWzpjaWRyXQoKICAgICMgdHVybiBhbGwgaG9zdCBiaXRzIG9uL29mZgogICAgd2hpbGUgbGVuKHN0YXJ0KSA8IDMyOgogICAgICAgIHN0YXJ0ID0gc3RhcnQgKyAnMCcKICAgIHdoaWxlIGxlbihzdG9wKSA8IDMyOgogICAgICAgIHN0b3AgPSBzdG9wICsgJzEnCgogICAgIyBjb252ZXJ0IGJhY2sgdG8gb2N0ZXRzCiAgICBzdGFydF9vY3RldHMgPSBbaW50KHN0YXJ0Wzo4XSwgMiksIGludChzdGFydFs4OjE2XSwgMiksIGludChzdGFydFsxNjoyNF0sIDIpLCBpbnQoc3RhcnRbMjQ6XSwgMildCiAgICBzdG9wX29jdGV0cyA9IFtpbnQoc3RvcFs6OF0sIDIpLCBpbnQoc3RvcFs4OjE2XSwgMiksIGludChzdG9wWzE2OjI0XSwgMiksIGludChzdG9wWzI0Ol0sIDIpXQoKICAgIGlwcyA9IFtdCiAgICBmb3IgYSBpbiByYW5nZShzdGFydF9vY3RldHNbMF0sIHN0b3Bfb2N0ZXRzWzBdKzEpOgogICAgICAgIGZvciBiIGluIHJhbmdlKHN0YXJ0X29jdGV0c1sxXSwgc3RvcF9vY3RldHNbMV0rMSk6CiAgICAgICAgICAgIGZvciBjIGluIHJhbmdlKHN0YXJ0X29jdGV0c1syXSwgc3RvcF9vY3RldHNbMl0rMSk6CiAgICAgICAgICAgICAgICBmb3IgZCBpbiByYW5nZShzdGFydF9vY3RldHNbM10sIHN0b3Bfb2N0ZXRzWzNdKzEpOgogICAgICAgICAgICAgICAgICAgIGlmIGQgPT0gMCBvciBkPT0gMjU1OgogICAgICAgICAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICAgICAgICAgIGlwcy5hcHBlbmQoc3RyKGEpKyIuIitzdHIoYikrIi4iK3N0cihjKSsiLiIrc3RyKGQpKQoKICAgIHJldHVybiBpcHMKCiMgc3RlcCAxLCBnZXQgdGhlIGludGVyZmFjZSByYW5nZXMKaW50ZXJmYWNlcyA9IG9zLnBvcGVuKCJpcCBhIHwgZ3JlcCBnbG9iYWwgfCBhd2sgJ3twcmludCAkMn0nIikucmVhZCgpLnN0cmlwKCkuc3BsaXQoKQoKb25saW5lX2lwcyA9IFtdCiMgc3RlcCAyLCBleHBhbmQgdGhlIGNpZHJzIHRvIGEgZnVsbCBJUCBsaXN0LCBwaW5nIHN3ZWVwIGJlZm9yZSBhIHBvcnQgc2Nhbgpmb3IgaSBpbiBpbnRlcmZhY2VzOgogICAgaXBzID0gZXhwYW5kX2NpZHIoaSkKICAgIGZvciBpcCBpbiBpcHM6CiAgICAgICAgcmVzdWx0ID0gb3MucG9wZW4oInBpbmcgIitpcCsiIC1jIDEgLVcgMC4yIikucmVhZCgpCiAgICAgICAgaWYgIjEwMCUgcGFja2V0IGxvc3MiIG5vdCBpbiByZXN1bHQ6CiAgICAgICAgICAgICMgY2hlY2sgdGhlIG1vc3QgY29tbW9uIHBvcnRzCiAgICAgICAgICAgIG9wZW5fcG9ydHMgPSBwb3J0X3NjYW5fY29tbW9uX3BvcnRzKGlwKQogICAgICAgICAgICBwcmludChpcCsiIGlzIG9ubGluZSB3aXRoICIrc3RyKGxlbihvcGVuX3BvcnRzKSkrIiBvcGVuIFRDUCBwb3J0cy4iKQogICAgICAgICAgICBwcmludChvcGVuX3BvcnRzKQpFTkQK | base64 --decode | bash`

# Linux Python FTP/HTTP Heavy Banner Grabbing
`echo IyEvYmluL2Jhc2gKCnB5dGhvbiA8PCBFTkQKaW1wb3J0IHNvY2tldCwgcmFuZG9tLCBvcywgdGltZSwgc3lzCgojIHRoaXMgaXMgcHl0aG9uIHZlcnNpb24gYWdub3N0aWMgdG8gaGFuZGxlIGJvdGgKIyBweXRob24zIGFuZCBweXRob24yIHdpdGggb25seSBzdGFuZGFyZCBpbXBvcnRzCmRlZiBzX3RvX2J5dGVzKHMpOgogICAgaWYgc3lzLnZlcnNpb25faW5mbyA8ICgzLCAwKToKICAgICAgICByZXR1cm4gYnl0ZXMocykKICAgIGVsc2U6CiAgICAgICAgcmV0dXJuIGJ5dGVzKHMsICd1dGY4JykKCmRlZiBjaWRyX2NvbnRhaW5zKG5ldCwgdGFyZ2V0KToKICAgIHRyeToKICAgICAgICBjaWRyID0gaW50KG5ldC5zcGxpdCgiLyIpWy0xXSkKICAgIGV4Y2VwdDoKICAgICAgICByZXR1cm4gW10KICAgIHRyeToKICAgICAgICBvY3RldHMgPSBbaW50KG8pIGZvciBvIGluIG5ldC5zcGxpdCgiLyIpWzBdLnNwbGl0KCIuIildCiAgICBleGNlcHQ6CiAgICAgICAgcmV0dXJuIFtdCgogICAgIyBnZXQgdGhlIG5ldHdvcmsgYml0czogJzBiMTEnCiAgICBiaW5faXAgPSAnJwogICAgZm9yIG8gaW4gb2N0ZXRzOgogICAgICAgIGJpbl9zdHIgPSBiaW4obylbMjpdCiAgICAgICAgd2hpbGUgbGVuKGJpbl9zdHIpIDwgODoKICAgICAgICAgICAgYmluX3N0ciA9ICcwJytiaW5fc3RyCgogICAgICAgIGJpbl9pcCA9IGJpbl9pcCArIGJpbl9zdHIKCiAgICBzdGFydCA9IGJpbl9pcFs6Y2lkcl0KICAgIHN0b3AgPSBiaW5faXBbOmNpZHJdCgogICAgIyB0dXJuIGFsbCBob3N0IGJpdHMgb24vb2ZmCiAgICB3aGlsZSBsZW4oc3RhcnQpIDwgMzI6CiAgICAgICAgc3RhcnQgPSBzdGFydCArICcwJwogICAgd2hpbGUgbGVuKHN0b3ApIDwgMzI6CiAgICAgICAgc3RvcCA9IHN0b3AgKyAnMScKCiAgICAjIGNvbnZlcnQgYmFjayB0byBvY3RldHMKICAgIHN0YXJ0X29jdGV0cyA9IFtpbnQoc3RhcnRbOjhdLCAyKSwgaW50KHN0YXJ0Wzg6MTZdLCAyKSwgaW50KHN0YXJ0WzE2OjI0XSwgMiksIGludChzdGFydFsyNDpdLCAyKV0KICAgIHN0b3Bfb2N0ZXRzID0gW2ludChzdG9wWzo4XSwgMiksIGludChzdG9wWzg6MTZdLCAyKSwgaW50KHN0b3BbMTY6MjRdLCAyKSwgaW50KHN0b3BbMjQ6XSwgMildCgogICAgZm9yIGEgaW4gcmFuZ2Uoc3RhcnRfb2N0ZXRzWzBdLCBzdG9wX29jdGV0c1swXSsxKToKICAgICAgICBmb3IgYiBpbiByYW5nZShzdGFydF9vY3RldHNbMV0sIHN0b3Bfb2N0ZXRzWzFdKzEpOgogICAgICAgICAgICBmb3IgYyBpbiByYW5nZShzdGFydF9vY3RldHNbMl0sIHN0b3Bfb2N0ZXRzWzJdKzEpOgogICAgICAgICAgICAgICAgZm9yIGQgaW4gcmFuZ2Uoc3RhcnRfb2N0ZXRzWzNdLCBzdG9wX29jdGV0c1szXSsxKToKICAgICAgICAgICAgICAgICAgICBpcCA9IHN0cihhKSsiLiIrc3RyKGIpKyIuIitzdHIoYykrIi4iK3N0cihkKQogICAgICAgICAgICAgICAgICAgIGlmIGlwID09IHRhcmdldDoKICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG5ldC5zcGxpdCgiLyIpWzBdCgojIGZvciBhbm9ueW1vdXMgRlRQLCBqdXN0IHVzZSBjcmVkX2Z0cCgiYW5vbnltb3VzIiwgIiIsIDEuMS4xLjEpCmRlZiBjcmVkX2Z0cCh1c2VybmFtZSwgcGFzc3dvcmQsIGlwKToKICAgIHRyeToKICAgICAgICBzID0gc29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCwgc29ja2V0LlNPQ0tfU1RSRUFNKQogICAgICAgIHMuc2V0dGltZW91dCg1KQogICAgICAgIHMuY29ubmVjdCgoaXAsIDIxKSkKICAgIGV4Y2VwdDoKICAgICAgICByZXR1cm4gIkZUUCBFUlJPUjogRmFpbGVkIHRvIGNvbm5lY3QgdG8gVENQIHNvY2tldC4iCiAgICAjIG1ha2Ugc3VyZSB0aGlzIGlzIGFuIEZUUCBzZXJ2ZXIKICAgIGRhdGEgPSBzLnJlY3YoMjA0OCkKICAgIGlmIGInRlRQJyBub3QgaW4gZGF0YSBhbmQgYidmdHAnIG5vdCBpbiBkYXRhOgogICAgICAgIHByaW50KGRhdGEpCiAgICAgICAgcmV0dXJuICJGVFAgRVJST1I6IEZUUCBiYW5uZXIgYWJzZW50LiIKCiAgICAjIHNlbmQgdGhlIHVzZXJuYW1lCiAgICB1c2VybmFtZSA9IHNfdG9fYnl0ZXMoJ1VTRVIgJyt1c2VybmFtZSsiXHJcbiIpCiAgICBzLnNlbmQodXNlcm5hbWUpCgogICAgIyBtYWtlIHN1cmUgdGhhdCB3YXMgYWNjZXB0ZWQKICAgIHByaW50KCJTZW50IHVzZXJuYW1lOiIpCiAgICBkYXRhID0gcy5yZWN2KDIwNDgpCiAgICBwcmludChkYXRhKQoKICAgICMgc2VuZCBhbiBlbXB0eSBwYXNzd29yZAogICAgcGFzc3dvcmQgPSBzX3RvX2J5dGVzKCJQQVNTICIrcGFzc3dvcmQrIlxyXG4iKQogICAgcy5zZW5kKHBhc3N3b3JkKQoKICAgICMgbWFrZSBzdXJlIHRoZSBjcmVkZW50aWFscyB3ZXJlIGFjY2VwdGVkCiAgICBwcmludCgiU2VudCBwYXNzd29yZDoiKQogICAgZGF0YSA9IHMucmVjdigyMDQ4KQogICAgcHJpbnQoZGF0YSkKCiAgICBwcmludCgiU2VuZGluZyBTWVNULi4uIikKICAgIHMuc2VuZChiJ1NZU1RcclxuJykKICAgIGRhdGEgPSBzLnJlY3YoMjA0OCkKICAgIHByaW50KGRhdGEpCgogICAgIyBzZXQgdXAgYSBUQ1AgbGlzdGVuZXIgZm9yIGEgcG9ydCBjb21tYW5kLCB0aGlzIGlzIGZyb20gdGhlIFJGQwogICAgIyB3ZSBuZWVkIHRvIHNlbmQgdHdvIGJ5dGVzLCByZXByZXNlbnRlZCBhcyBjb21tYS1zZXBhcmF0ZWQgaW50ZWdlciBzdHJpbmdzCiAgICAjIHRoYXQgdGhlIHNlcnZlciB3aWxsIGNvbWJpbmUgdG8gc2V0IHVwIGEgVENQIHNvY2tldCwgdHJhbnNmZXIgdGhlIGRhdGEKICAgICMgYW5kIGZpbmFsbHkgdGVhciBpdCBkb3duCiAgICBsb2NhbF9wb3J0ID0gcmFuZG9tLnJhbmRpbnQoMzgwMDAsIDM5OTk5KQogICAgcG9ydF9ieXRlXzEgPSBzdHIobG9jYWxfcG9ydCA+PiA4KQogICAgcG9ydF9ieXRlXzIgPSBzdHIobG9jYWxfcG9ydCAmIDI1NSkKICAgIHByaW50KCIxOiIrcG9ydF9ieXRlXzEpCiAgICBwcmludCgiMjoiK3BvcnRfYnl0ZV8yKQoKICAgICMgdGhlcmUgY291bGQgYmUgbXVsdGlwbGUgaW50ZXJmYWNlcywgd2UgbmVlZCB0byBmaW5kIHdoaWNoIGludGVyZmFjZSBoYXMKICAgICMgdGhlIGNpZHIgcmFuZ2UgdGhhdCBjb250YWlucyB0aGUgdGFyZ2V0IElQIGFuZCBwcmVzZW50IHRoYXQgYXMgdGhlIGxpc3RlbmVyCiAgICAjIGZvciB0aGUgZGF0YSBwb3J0IG9mIHRoZSBwb3J0IGNvbW1hbmQKICAgIGludGVyZmFjZV9yYW5nZXMgPSBvcy5wb3BlbigiaXAgYSB8IGdyZXAgZ2xvYmFsIHwgYXdrICd7cHJpbnQgJDJ9JyIpLnJlYWQoKS5zdHJpcCgpLnNwbGl0KCkKICAgIHNvdXJjZSA9IE5vbmUKICAgIHByaW50KCJDaGVja2luZyBmb3IgcmV0dXJuIGlwLi4uIikKICAgIHByaW50KGludGVyZmFjZV9yYW5nZXMpCiAgICBmb3IgaW50ZXJmYWNlIGluIGludGVyZmFjZV9yYW5nZXM6CiAgICAgICAgcHJpbnQoIkNoZWNraW5nICIraW50ZXJmYWNlKQogICAgICAgIHNvdXJjZSA9IGNpZHJfY29udGFpbnMoaW50ZXJmYWNlLCBpcCkKICAgICAgICBwcmludChzb3VyY2UpCiAgICAgICAgaWYgc291cmNlICE9IE5vbmUgYW5kIGxlbihzb3VyY2UpID4gMDoKICAgICAgICAgICAgYnJlYWsKICAgIHByaW50KCJQcmVzZW50aW5nIHJldHVybiBJUCBhcyAiK3NvdXJjZSsiOiIrc3RyKGxvY2FsX3BvcnQpKQoKICAgICMgc2V0IHVwIHRoZSBsaXN0ZW5lciBmb3IgdGhlIEZUUC1EQVRBIHN0cmVhbQogICAgcHJpbnQoIkNyZWF0aW5nIGxpc3RlbmVyLi4uIikKICAgIGxpc3RlbmVyID0gc29ja2V0LnNvY2tldCgpCiAgICBsaXN0ZW5lci5iaW5kKCgnMC4wLjAuMCcsIGxvY2FsX3BvcnQpKQogICAgbGlzdGVuZXIubGlzdGVuKDIpCgogICAgcHJpbnQoIlNlbmRpbmcgcG9ydCBjb21tYW5kLi4uIikKICAgICMgc2VuZCB0aGUgcG9ydCBjb21tYW5kIGZvciB0aGUgbmV3IGxpc3RlbmVyCiAgICBwb3J0X2NvbW1hbmQgPSAiUE9SVCAiK3NvdXJjZS5yZXBsYWNlKCIuIiwgIiwiKSsiLCIrcG9ydF9ieXRlXzErIiwiK3BvcnRfYnl0ZV8yKyJcclxuIgogICAgcy5zZW5kKHNfdG9fYnl0ZXMocG9ydF9jb21tYW5kKSkKICAgIGRhdGEgPSBzLnJlY3YoMjA0OCkKICAgIHByaW50KGRhdGEpCgogICAgcHJpbnQoIlNlbmRpbmcgTElTVCBjb21tYW5kLi4uIikKICAgIHMuc2VuZChiJ0xJU1RcclxuJykKICAgIGRhdGEgPSBzLnJlY3YoMjA0OCkKICAgIHByaW50KGRhdGEpCgogICAgIyBhY2NlcHQgdGhlIGluY29taW5nIHJlcXVlc3QgYW5kIGdldCB0aGUgZGF0YQogICAgY29ubiwgYWRkciA9IGxpc3RlbmVyLmFjY2VwdCgpCgogICAgcHJpbnQoIlJlY2VpdmluZyBjb21tYW5kIGRhdGEgZnJvbSAiK3N0cihhZGRyKSkKCiAgICAjIHJlY2VpdmUgYWxsIHRoZSBkYXRhCiAgICBmdWxsX3N0ciA9ICIiCiAgICB3aGlsZSBUcnVlOgogICAgICAgIGRhdGEgPSBjb25uLnJlY3YoMTAyNCkKICAgICAgICBpZiBsZW4oZGF0YSkgPiAzOgogICAgICAgICAgICBmdWxsX3N0ciA9IGZ1bGxfc3RyICsgc3RyKGRhdGEpWzI6LTFdCiAgICAgICAgaWYgbm90IGRhdGE6CiAgICAgICAgICAgIGJyZWFrCiAgICBjb25uLmNsb3NlKCkKCiAgICAjIHBhcnNlIHRoZSBmaWxlbmFtZXMgZm9yIGVhY2ggZmlsZSwgc2VuZCBhbiBpbmRpdmlkdWFsIHBvcnQgY29tbWFuZCBmb3IgZWFjaCBmaWxlIHdlIG5lZWQgdG8gcmV0cmlldmUKICAgIGxpbmVzID0gZnVsbF9zdHIuc3BsaXQoIlxcclxcbiIpCiAgICBmaWxlbmFtZXMgPSBbXQogICAgcHJpbnQoIkZpbGUgbGlzdGluZzoiKQogICAgZm9yIGxpbmUgaW4gbGluZXM6CiAgICAgICAgIyB0cnkgdG8gZXhjbHVkZSBkaXJlY3RvcmllcwogICAgICAgIGlmIGxlbihsaW5lKSA9PSAwIG9yICcgJyBub3QgaW4gbGluZSBvciBsaW5lWzBdID09ICdkJzoKICAgICAgICAgICAgY29udGludWUKICAgICAgICBwcmludChsaW5lKQogICAgICAgIGZpbGVuYW1lcy5hcHBlbmQobGluZS5zcGxpdCgpWy0xXSkKICAgIHByaW50KCItLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0iKQogICAgZGF0YSA9IHMucmVjdigyMDQ4KQogICAgcHJpbnQoZGF0YSkKCiAgICAjIHJ1biBhIHBvcnQgY29tbWFuZCBhbmQgUkVUUiBmb3IgZWFjaCBmaWxlCiAgICBmb3IgZiBpbiBmaWxlbmFtZXM6CiAgICAgICAgcHJpbnQoIkdldHRpbmcgZmlsZSBjb250ZW50IGZvciAiK2YpCiAgICAgICAgdGltZS5zbGVlcCgwLjEpCgogICAgICAgIGxvY2FsX3BvcnQgPSByYW5kb20ucmFuZGludCgzODAwMCwgMzk5OTkpCiAgICAgICAgcG9ydF9ieXRlXzEgPSBzdHIobG9jYWxfcG9ydCA+PiA4KQogICAgICAgIHBvcnRfYnl0ZV8yID0gc3RyKGxvY2FsX3BvcnQgJiAyNTUpCiAgICAgICAgcHJpbnQoIjE6Iitwb3J0X2J5dGVfMSkKICAgICAgICBwcmludCgiMjoiK3BvcnRfYnl0ZV8yKQoKICAgICAgICBpbnRlcmZhY2VfcmFuZ2VzID0gb3MucG9wZW4oImlwIGEgfCBncmVwIGdsb2JhbCB8IGF3ayAne3ByaW50ICQyfSciKS5yZWFkKCkuc3RyaXAoKS5zcGxpdCgpCiAgICAgICAgc291cmNlID0gTm9uZQogICAgICAgIHByaW50KCJDaGVja2luZyBmb3IgcmV0dXJuIGlwLi4uIikKICAgICAgICBwcmludChpbnRlcmZhY2VfcmFuZ2VzKQogICAgICAgIGZvciBpbnRlcmZhY2UgaW4gaW50ZXJmYWNlX3JhbmdlczoKICAgICAgICAgICAgcHJpbnQoIkNoZWNraW5nICIraW50ZXJmYWNlKQogICAgICAgICAgICBzb3VyY2UgPSBjaWRyX2NvbnRhaW5zKGludGVyZmFjZSwgaXApCiAgICAgICAgICAgIHByaW50KHNvdXJjZSkKICAgICAgICAgICAgaWYgc291cmNlICE9IE5vbmUgYW5kIGxlbihzb3VyY2UpID4gMDoKICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgcHJpbnQoIlByZXNlbnRpbmcgcmV0dXJuIElQIGFzICIrc291cmNlKyI6IitzdHIobG9jYWxfcG9ydCkpCgogICAgICAgICMgc2V0IHVwIHRoZSBsaXN0ZW5lciBmb3IgdGhlIEZUUC1EQVRBIHN0cmVhbQogICAgICAgIHByaW50KCJDcmVhdGluZyBsaXN0ZW5lci4uLiIpCiAgICAgICAgdG1wbGlzdGVuZXIgPSBzb2NrZXQuc29ja2V0KCkKICAgICAgICB0bXBsaXN0ZW5lci5iaW5kKCgnMC4wLjAuMCcsIGxvY2FsX3BvcnQpKQogICAgICAgIHRtcGxpc3RlbmVyLmxpc3RlbigyKQoKICAgICAgICBwcmludCgiU2VuZGluZyBwb3J0IGNvbW1hbmQuLi4iKQogICAgICAgICMgc2VuZCB0aGUgcG9ydCBjb21tYW5kIGZvciB0aGUgbmV3IGxpc3RlbmVyCiAgICAgICAgcG9ydF9jb21tYW5kID0gIlBPUlQgIitzb3VyY2UucmVwbGFjZSgiLiIsICIsIikrIiwiK3BvcnRfYnl0ZV8xKyIsIitwb3J0X2J5dGVfMisiXHJcbiIKICAgICAgICBzLnNlbmQoc190b19ieXRlcyhwb3J0X2NvbW1hbmQpKQogICAgICAgIGRhdGEgPSBzLnJlY3YoMjA0OCkKICAgICAgICBwcmludChkYXRhKQoKICAgICAgICAjIHNlbmQgdGhlIGNvbW1hbmQgdG8gZG93bmxvYWQgdGhlIGZpbGUKICAgICAgICBwcmludCgiU2VuZGluZyBSRVRSIGNvbW1hbmQuLi4iKQogICAgICAgIHJldHIgPSBzX3RvX2J5dGVzKCJSRVRSICIrZisiXHJcbiIpCiAgICAgICAgcy5zZW5kKHJldHIpCiAgICAgICAgZGF0YSA9IHMucmVjdigyMDQ4KQogICAgICAgIHByaW50KGRhdGEpCiAgICAgICAgaWYgYidOb3QgYSBmaWxlJyBpbiBkYXRhIG9yIGInbm90IGEgZmlsZScgaW4gZGF0YToKICAgICAgICAgICAgcHJpbnQoZisiIGlzIG5vdCBhIGZpbGUsIGNvbnRpbnVpbmcuLi4iKQogICAgICAgICAgICB0bXBsaXN0ZW5lci5jbG9zZSgpCiAgICAgICAgICAgIHByaW50KCItLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0iKQogICAgICAgICAgICBjb250aW51ZQoKICAgICAgICAjIGFjY2VwdCB0aGUgaW5jb21pbmcgcmVxdWVzdCBhbmQgZ2V0IHRoZSBkYXRhCiAgICAgICAgY29ubiwgYWRkciA9IHRtcGxpc3RlbmVyLmFjY2VwdCgpCgogICAgICAgIHByaW50KCJSZWNlaXZpbmcgY29tbWFuZCBkYXRhIGZyb20gIitzdHIoYWRkcikpCgogICAgICAgICMgcmVjZWl2ZSBhbGwgdGhlIGRhdGEKICAgICAgICBmdWxsX3N0ciA9ICIiCiAgICAgICAgd2hpbGUgVHJ1ZToKICAgICAgICAgICAgZGF0YSA9IGNvbm4ucmVjdigyNTYpCiAgICAgICAgICAgIHByaW50KGRhdGEpCiAgICAgICAgICAgIGlmIG5vdCBkYXRhOgogICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICBjb25uLmNsb3NlKCkKCiAgICAgICAgcHJpbnQoIi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSIpCgogICAgcHJpbnQoZmlsZW5hbWVzKQogICAgcy5jbG9zZSgpCgogICAgbGlzdGVuZXIuY2xvc2UoKQoKZGVmIGdyZWVuKHRleHQpOgogICAgcmV0dXJuKCdcMDMzWzkybScrdGV4dCsnXDAzM1swbScpCgpkZWYgeWVsbG93KHRleHQpOgogICAgcmV0dXJuKCdcMDMzWzkzbScrdGV4dCsnXDAzM1swbScpCgpjb21tb25fcG9ydHMgPSBbMjIsIDIwLCAyMSwgMjMsIDI1LCA1MywgNjksIDgwLCA4OCwgMzM4OV0KCiMgbWFrZSBhIHdlYiByZXF1ZXN0IHRvIGEgc3RhbmRhcmQgaHR0cCBwb3J0ICg4MCkgdXNpbmcgb25seSB0aGUgc29ja2V0IGxpYnJhcnkKZGVmIGh0dHBfcmVxdWVzdChpcCk6CiAgICBzID0gc29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCwgc29ja2V0LlNPQ0tfU1RSRUFNKQogICAgcy5zZXR0aW1lb3V0KDMpCiAgICBzLmNvbm5lY3QoKGlwLCA4MCkpCiAgICBnZXRfcmVxdWVzdCA9IGInR0VUIC8gSFRUUC8xLjFcclxuVXNlci1BZ2VudDogY3VybC83LjMzLjBcclxuSG9zdDogMTI3LjAuMC4xXHJcbkFjY2VwdDogKi8qXHJcblxyXG4nCiAgICBzLnNlbmQoZ2V0X3JlcXVlc3QpCiAgICBkYXRhID0gcy5yZWN2KDIwNDgpCiAgICBzLmNsb3NlKCkKICAgIHJldHVybiBkYXRhCgpkZWYgYmFubmVyX2dyYWIoaXAsIHBvcnQpOgogICAgaWYgcG9ydCA9PSA4MDoKICAgICAgICByZXR1cm4gIkhUVFAgU2l0ZSBMb2FkOlxuIitzdHIoaHR0cF9yZXF1ZXN0KGlwKSkrIlxuLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIgogICAgaWYgcG9ydCA9PSAyMToKICAgICAgICBwcmludCgiRlRQIEZpbGUgRW51bWVyYXRpb246IikKICAgICAgICBjcmVkX2Z0cCgiYW5vbnltb3VzIiwgIiIsIGlwKQogICAgICAgIHJldHVybiAiRlRQIEVOVU1FUkFUSU9OIENPTVBMRVRFXG4tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0iCgogICAgdHJ5OgogICAgICAgIHMgPSBzb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULCBzb2NrZXQuU09DS19TVFJFQU0pCiAgICAgICAgcy5zZXR0aW1lb3V0KDEpCiAgICAgICAgcy5jb25uZWN0KChpcCwgcG9ydCkpCiAgICAgICAgZGF0YSA9IHMucmVjdigxMjgpCiAgICAgICAgcy5jbG9zZSgpCiAgICAgICAgcmV0dXJuICJCQU5ORVIgR1JBQjoiK3N0cihkYXRhKS5zdHJpcCgpCiAgICBleGNlcHQ6CiAgICAgICAgcmV0dXJuICJCQU5ORVIgR1JBQjogVENQIENvbm5lY3QgRXJyb3IuIgoKZGVmIHBvcnRfc2Nhbl9jb21tb25fcG9ydHMoaXApOgogICAgb3Blbl9wb3J0cyA9IDAKICAgIGZvciBwb3J0IGluIGNvbW1vbl9wb3J0czoKICAgICAgICBzID0gc29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCwgc29ja2V0LlNPQ0tfU1RSRUFNKQogICAgICAgIHMuc2V0dGltZW91dCgwLjIpCiAgICAgICAgYmFubmVyID0gJycKCiAgICAgICAgdHJ5OgogICAgICAgICAgICBzLmNvbm5lY3QoKGlwLHBvcnQpKQogICAgICAgICAgICBzLmNsb3NlKCkKICAgICAgICAgICAgcHJpbnQoeWVsbG93KHN0cihwb3J0KSkrIi9UQ1AgaXMgT1BFTjtcdCIrYmFubmVyX2dyYWIoaXAsIHBvcnQpKQogICAgICAgICAgICBvcGVuX3BvcnRzICs9IDEKICAgICAgICBleGNlcHQ6CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICBpZiBvcGVuX3BvcnRzID09IDA6CiAgICAgICAgcHJpbnQoIk5vIG9wZW4gcG9ydHMgZm91bmQgKHJlLXNjYW4gZm9yIGFsbCBwb3J0cykiKQoKZGVmIGV4cGFuZF9jaWRyKG5ldCk6CiAgICB0cnk6CiAgICAgICAgY2lkciA9IGludChuZXQuc3BsaXQoIi8iKVstMV0pCiAgICBleGNlcHQ6CiAgICAgICAgcmV0dXJuIFtdCiAgICB0cnk6CiAgICAgICAgb2N0ZXRzID0gW2ludChvKSBmb3IgbyBpbiBuZXQuc3BsaXQoIi8iKVswXS5zcGxpdCgiLiIpXQogICAgZXhjZXB0OgogICAgICAgIHJldHVybiBbXQoKICAgICMgZ2V0IHRoZSBuZXR3b3JrIGJpdHM6ICcwYjExJwogICAgYmluX2lwID0gJycKICAgIGZvciBvIGluIG9jdGV0czoKICAgICAgICBiaW5fc3RyID0gYmluKG8pWzI6XQogICAgICAgIHdoaWxlIGxlbihiaW5fc3RyKSA8IDg6CiAgICAgICAgICAgIGJpbl9zdHIgPSAnMCcrYmluX3N0cgoKICAgICAgICBiaW5faXAgPSBiaW5faXAgKyBiaW5fc3RyCgogICAgc3RhcnQgPSBiaW5faXBbOmNpZHJdCiAgICBzdG9wID0gYmluX2lwWzpjaWRyXQoKICAgICMgdHVybiBhbGwgaG9zdCBiaXRzIG9uL29mZgogICAgd2hpbGUgbGVuKHN0YXJ0KSA8IDMyOgogICAgICAgIHN0YXJ0ID0gc3RhcnQgKyAnMCcKICAgIHdoaWxlIGxlbihzdG9wKSA8IDMyOgogICAgICAgIHN0b3AgPSBzdG9wICsgJzEnCgogICAgIyBjb252ZXJ0IGJhY2sgdG8gb2N0ZXRzCiAgICBzdGFydF9vY3RldHMgPSBbaW50KHN0YXJ0Wzo4XSwgMiksIGludChzdGFydFs4OjE2XSwgMiksIGludChzdGFydFsxNjoyNF0sIDIpLCBpbnQoc3RhcnRbMjQ6XSwgMildCiAgICBzdG9wX29jdGV0cyA9IFtpbnQoc3RvcFs6OF0sIDIpLCBpbnQoc3RvcFs4OjE2XSwgMiksIGludChzdG9wWzE2OjI0XSwgMiksIGludChzdG9wWzI0Ol0sIDIpXQoKICAgIGlwcyA9IFtdCiAgICBmb3IgYSBpbiByYW5nZShzdGFydF9vY3RldHNbMF0sIHN0b3Bfb2N0ZXRzWzBdKzEpOgogICAgICAgIGZvciBiIGluIHJhbmdlKHN0YXJ0X29jdGV0c1sxXSwgc3RvcF9vY3RldHNbMV0rMSk6CiAgICAgICAgICAgIGZvciBjIGluIHJhbmdlKHN0YXJ0X29jdGV0c1syXSwgc3RvcF9vY3RldHNbMl0rMSk6CiAgICAgICAgICAgICAgICBmb3IgZCBpbiByYW5nZShzdGFydF9vY3RldHNbM10sIHN0b3Bfb2N0ZXRzWzNdKzEpOgogICAgICAgICAgICAgICAgICAgIGlmIGQgPT0gMCBvciBkPT0gMjU1OgogICAgICAgICAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICAgICAgICAgIGlwcy5hcHBlbmQoc3RyKGEpKyIuIitzdHIoYikrIi4iK3N0cihjKSsiLiIrc3RyKGQpKQoKICAgIHJldHVybiBpcHMKCiMgc3RlcCAxLCBnZXQgdGhlIGludGVyZmFjZSByYW5nZXMKaW50ZXJmYWNlcyA9IG9zLnBvcGVuKCJpcCBhIHwgZ3JlcCBnbG9iYWwgfCBhd2sgJ3twcmludCAkMn0nIikucmVhZCgpLnN0cmlwKCkuc3BsaXQoKQoKb25saW5lX2lwcyA9IFtdCiMgc3RlcCAyLCBleHBhbmQgdGhlIGNpZHJzIHRvIGEgZnVsbCBJUCBsaXN0LCBwaW5nIHN3ZWVwIGJlZm9yZSBhIHBvcnQgc2NhbgppbmRleCA9IC0xCmZvciBpIGluIGludGVyZmFjZXM6CiAgICBpbmRleCArPSAxCiAgICBpcHMgPSBleHBhbmRfY2lkcihpKQogICAgaWYgbGVuKGlwcykgPT0gMDoKICAgICAgICBjb250aW51ZQoKICAgIG4gPSBvcy5wb3BlbigiaXAgYSB8IGdyZXAgIitpKS5yZWFkKCkuc3BsaXQoKVstMV0KICAgIHByaW50KCJcbkludGVyZmFjZSAiK24rIiAiK3N0cihsZW4oaXBzKSkrIiBhZGRyZXNzZXMgaW4gIitpKQogICAgZm9yIGlwIGluIGlwczoKICAgICAgICAjIHNjYW4gYSBsb3cgcG9ydCB3aXRob3V0IHVzaW5nIHBpbmcgc28gdGhpcyBjYW4gcnVuIHdpdGggbWluaW1hbCBwZXJtaXNzaW9ucwogICAgICAgIHMgPSBzb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULCBzb2NrZXQuU09DS19TVFJFQU0pCiAgICAgICAgcy5zZXR0aW1lb3V0KDAuMikKCiAgICAgICAgaG9zdF9vbmxpbmUgPSBGYWxzZQogICAgICAgIHRyeToKICAgICAgICAgICAgY29uID0gcy5jb25uZWN0KChpcCwxMCkpCiAgICAgICAgICAgIGNvbi5jbG9zZSgpCiAgICAgICAgICAgIGhvc3Rfb25saW5lID0gVHJ1ZQogICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZXJyb3I6CiAgICAgICAgICAgIGlmICJDb25uZWN0aW9uIHJlZnVzZWQiIGluIHN0cihlcnJvcik6CiAgICAgICAgICAgICAgICBob3N0X29ubGluZSA9IFRydWUKICAgICAgICBpZiBob3N0X29ubGluZToKICAgICAgICAgICAgIyBjaGVjayB0aGUgbW9zdCBjb21tb24gcG9ydHMKICAgICAgICAgICAgcHJpbnQoZ3JlZW4oaXApKyIgaXMgb25saW5lLCBjaGVja2luZyBUQ1AgcG9ydHMuLi4iKQogICAgICAgICAgICBwb3J0X3NjYW5fY29tbW9uX3BvcnRzKGlwKQoKRU5ECg== | base64 --decode | sh`
