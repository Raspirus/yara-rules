rule ELASTIC_Linux_Trojan_Tsunami_9Ce5B69F : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "9ce5b69f-4938-4576-89da-8dcd492708ed"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L141-L159"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ad63fbd15b7de4da0db1b38609b7481253c100e3028c19831a5d5c1926351829"
		logic_hash = "b9756eb99e59ba3a9a616b391bcf26bda26a6ac0de115460f9ba52129f590764"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "90fece6c2950467d78c8a9f1d72054adf854f19cdb33e71db0234a7b0aebef47"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F4 8B 54 85 B4 8B 45 E4 8D 04 02 C6 00 00 FF 45 F4 8B 45 E4 01 }

	condition:
		all of them
}