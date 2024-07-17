
rule ELASTIC_Linux_Ransomware_Erebus_Ead4F55B : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Erebus (Linux.Ransomware.Erebus)"
		author = "Elastic Security"
		id = "ead4f55b-a4c6-46ff-bc8e-03831a17df9c"
		date = "2023-07-27"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Ransomware_Erebus.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6558330f07a7c90c40006346ed09e859b588d031193f8a9679fe11a85c8ccb37"
		logic_hash = "82e81577372298623ee3ed3583bb18b2c0cfff30abbacf2909e7efca35c83bd7"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "571832cc76322a95244b042ab9b358755a1be19260410658dc32c03c5cae7638"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "important files have been encrypted"
		$a2 = "max_size_mb"
		$a3 = "EREBUS IS BEST."

	condition:
		2 of them
}