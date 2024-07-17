
rule ELASTIC_Macos_Backdoor_Applejeus_31872Ae2 : FILE MEMORY
{
	meta:
		description = "Detects Macos Backdoor Applejeus (MacOS.Backdoor.Applejeus)"
		author = "Elastic Security"
		id = "31872ae2-f6df-4079-89c2-866cb2e62ec8"
		date = "2021-10-18"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Backdoor_Applejeus.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e352d6ea4da596abfdf51f617584611fc9321d5a6d1c22aff243aecdef8e7e55"
		logic_hash = "1d6f06668a7d048a93e53b294c5ab8ffe4cd610f3bef3fd80f14425ef8a85a29"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "24b78b736f691e6b84ba88b0bb47aaba84aad0c0e45cf70f2fa8c455291517df"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { FF CE 74 12 89 F0 31 C9 80 34 0F 63 48 FF C1 48 39 C8 75 F4 }

	condition:
		all of them
}