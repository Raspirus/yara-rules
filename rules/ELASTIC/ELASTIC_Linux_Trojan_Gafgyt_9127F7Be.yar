
rule ELASTIC_Linux_Trojan_Gafgyt_9127F7Be : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "9127f7be-6e82-46a1-9f11-0b3570b0cd76"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1050-L1068"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "899c072730590003b98278bdda21c15ecaa2f49ad51e417ed59e88caf054a72d"
		logic_hash = "2b1fa115598561e081dfb9b5f24f6728b0d52cb81ac7933728d81646f461bcae"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "72c742cb8b11ddf030e10f67e13c0392748dcd970394ec77ace3d2baa705a375"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E4 F7 E1 89 D0 C1 E8 03 89 45 E8 8B 45 E8 01 C0 03 45 E8 C1 }

	condition:
		all of them
}