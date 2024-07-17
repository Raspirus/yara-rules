
rule ELASTIC_Linux_Trojan_Dropperl_39F4Cd0D : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Dropperl (Linux.Trojan.Dropperl)"
		author = "Elastic Security"
		id = "39f4cd0d-4261-4d62-a527-f403edadbd0c"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Dropperl.yar#L121-L139"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c08e1347877dc77ad73c1e017f928c69c8c78a0e3c16ac5455668d2ad22500f3"
		logic_hash = "5b61f54604b110d2c8efaf1782a2e520baac96c6d3e8d1eda0877475c504bf89"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e1cdd678a1f46a3c6d26d53dd96ba6c6a45f97e743765c534f644af7c6450f8e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E8 ?? FA FF FF 83 7D D4 00 79 0A B8 ?? ?? 60 00 }

	condition:
		all of them
}