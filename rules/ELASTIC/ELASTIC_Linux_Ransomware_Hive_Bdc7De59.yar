rule ELASTIC_Linux_Ransomware_Hive_Bdc7De59 : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Hive (Linux.Ransomware.Hive)"
		author = "Elastic Security"
		id = "bdc7de59-bf12-461f-99e0-ec2532ace4e9"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Ransomware_Hive.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "713b699c04f21000fca981e698e1046d4595f423bd5741d712fd7e0bc358c771"
		logic_hash = "33908128258843d63c5dfe5acf15cfd68463f5cbdf08b88ef1bba394058a5a92"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "415ef589a1c2da6b16ab30fb68f938a9ee7917f5509f73aa90aeec51c10dc1ff"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 40 03 4C 39 C1 73 3A 4C 89 84 24 F0 00 00 00 48 89 D3 48 89 CF 4C }

	condition:
		all of them
}