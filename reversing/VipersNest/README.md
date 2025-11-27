# Viper's Nest [_snakeCTF 2025 Finals_]

**Category**: reversing/forensic

## Description

 A friend of mine got bitten by someone recently, can you find out more about whom?

## Solution



### First step: forensic analysis

The player was given a pcap file containing network traffic. Between a lot of encrypted traffic (TLS, QUIC, WireGuard),
it can be noticed a IMAP protocol (packet numner 12) containing an email with a suspicious attachment.

```aiignore
Content-Type: text/plain; charset=UTF-8; format=flowed
Content-Transfer-Encoding: 7bit

Hi Tonic Gin,

I'm sending over the comprehensive sales analysis for the Snake Plushies 
product line, covering the performance of the last trimester.

Attached is the file containing breakdown of the data, including sales 
volume by channel, regional distribution metrics, and an overview of 
market response.

I'd also like to schedule a meeting for tomorrow to discuss how to 
handle the potential demand spikes caused by the incoming SnakeCTF event.

Regards,
Hackermaan

--------------tmdsouKqW8vOZnFfQwQ6My1h
Content-Type: application/vnd.oasis.opendocument.spreadsheet;
 name="not_a_virus.ods"
Content-Disposition: attachment; filename="not_a_virus.ods"
Content-Transfer-Encoding: base64

UEsDBBQAAAgAAHZZb1uFbDmKLgAAAC4AAAAIAAAAbWltZXR5cGVhcHBsaWNhdGlvbi92bmQu
b2FzaXMub3BlbmRvY3VtZW50LnNwcmVhZHNoZWV0UEsDBBQACAgIAHZZb1sAAAAAAAAAAAAA
AAAfAAAAQmFzaWMvU3RhbmRhcmQvc2FmZXN0X21hY3JvLnhtbJVVbW8iNxD+zP6K6X6IoAKW
...
```

The attachment is an ODS file named `not_a_virus.ods` with a malicious macro. The macro downloads and executes a ps1 script
that we can revover from the network traffic. 
The script is split in 4 parts; his purpose is to download and execute a binary after setting up the correct envarioment with the argument `VipersNest`.


### Second step: Reversing the binary

The binary is an ELF stripped written in c++.

In short, it:
- tries to hide itself and avoid debugging
- decrypts the strings using chacha20
- finds the IP address of a C2 server by resolving a DNS name (that's were the DNS IP in the description comes from)
- connects to the C2 server and sends an authentication packet based on the argument passed to it (`VipersNest`)
- listens for commands from the C2 server and executes them

The commands had by be decrypted by xoring with 0xed. After that the format of a command message was:
- 4 bytes: time to wait before executing the command
- 1 byte: command type
- 1 byte: number of targets (n_t)
- n_t*4 bytes: targets IP addresses
- 1 byte: length of command args (l_d)
- for l_d times:
  - 1 byte: arg key
  - 1 byte: length of arg value (l_v)
  - l_v bytes: arg value
  
The supported commands were:
0) RCE: encrypted with chacha20, key and iv in args
1)  RickRoll: sends Never Gonna Give You Up to the target IPs
2) Stats: sends to c2 stats about the infected machine
3) steal_cookie: steals firefox cookies taking the profile name from args
4) flag: return data found in /flag.txt 
5) matrix: runs cmatrix effect on terminal
6) steal_profile: sends to c2 firefox profiles found in the machine
7) DDoS: target IP in args (removed so to not cause harm)

Important to note is that the returned data from "steal_profile" is in the form 
`INSERT INTO profiles (name) VALUES ('')`, this strongly hints to the presence of an SQL injection vulnerability.

### Third step: Getting the flag

Once the functionality of the binary is understood, the objective of the player is to extract the data inside the c2 server.
From the Firefox commands, we can see that there is an SQL injection vulnerability; by acting as a node of the botnet
we can wait for the firefox command to be sent and exploit the vulnerability to extract the database contents.

When a `steal_profile` command is sent, we can reply with a payload like:
```sql
INSERT INTO profiles (name) SELECT tbl_name FROM sqlite_master WHERE type='table'; --
```
and when the server sends back the data of the profile to steal the cookies we will receive the database schema and proceed in dumping the db where we can find the flag.