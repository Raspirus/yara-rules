
rule ELASTIC_Linux_Trojan_Dropperl_C4018572 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Dropperl (Linux.Trojan.Dropperl)"
		author = "Elastic Security"
		id = "c4018572-a8af-4204-bc19-284a2a27dfdd"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Dropperl.yar#L81-L99"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c1515b3a7a91650948af7577b613ee019166f116729b7ff6309b218047141f6d"
		logic_hash = "10d70540532c5c2984dc7e492672450924cb8f34c8158638191886057596b0a1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f2ede50ea639af593211c9ef03ee2847a32cf3eb155db4e2ca302f3508bf2a45"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E8 97 FB FF FF 83 7D D4 00 79 0A B8 ?? ?? 60 00 }

	condition:
		all of them
}