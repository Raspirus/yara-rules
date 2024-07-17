
rule TRELLIX_ARC_MINER_Monero_Mining_Detection : MINER FILE
{
	meta:
		description = "Monero mining software"
		author = "Trellix ATR team"
		id = "98ee7711-16ee-58e1-b52f-c68dd5f2b8a3"
		date = "2018-04-05"
		modified = "2022-01-19"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/miners/MINER_Monero.yar#L1-L43"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "4c1815186b0eb9e6be5fb0fcad02fd981ac9cf79c485fe12ce4a73054ef9fda2"
		score = 75
		quality = 70
		tags = "MINER, FILE"
		rule_version = "v1"
		malware_type = "miner"
		malware_family = "Ransom:W32/MoneroMiner"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$1 = "* COMMANDS:     'h' hashrate, 'p' pause, 'r' resume" fullword ascii
		$2 = "--cpu-affinity       set process affinity to CPU core(s), mask 0x3 for cores 0 and 1" fullword ascii
		$3 = "* THREADS:      %d, %s, av=%d, %sdonate=%d%%%s" fullword ascii
		$4 = "--user-agent         set custom user-agent string for pool" fullword ascii
		$5 = "-O, --userpass=U:P       username:password pair for mining server" fullword ascii
		$6 = "--cpu-priority       set process priority (0 idle, 2 normal to 5 highest)" fullword ascii
		$7 = "-p, --pass=PASSWORD      password for mining server" fullword ascii
		$8 = "* VERSIONS:     XMRig/%s libuv/%s%s" fullword ascii
		$9 = "-k, --keepalive          send keepalived for prevent timeout (need pool support)" fullword ascii
		$10 = "--max-cpu-usage=N    maximum CPU usage for automatic threads mode (default 75)" fullword ascii
		$11 = "--nicehash           enable nicehash/xmrig-proxy support" fullword ascii
		$12 = "<!--The ID below indicates application support for Windows 10 -->" fullword ascii
		$13 = "* CPU:          %s (%d) %sx64 %sAES-NI" fullword ascii
		$14 = "-r, --retries=N          number of times to retry before switch to backup server (default: 5)" fullword ascii
		$15 = "-B, --background         run the miner in the background" fullword ascii
		$16 = "* API PORT:     %d" fullword ascii
		$17 = "--api-access-token=T access token for API" fullword ascii
		$18 = "-t, --threads=N          number of miner threads" fullword ascii
		$19 = "--print-time=N       print hashrate report every N seconds" fullword ascii
		$20 = "-u, --user=USERNAME      username for mining server" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <4000KB and (8 of them )) or ( all of them )
}