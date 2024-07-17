rule ELASTIC_Linux_Trojan_Mobidash_Ddca1181 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mobidash (Linux.Trojan.Mobidash)"
		author = "Elastic Security"
		id = "ddca1181-91ca-4e5d-953f-be85838d3cb9"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mobidash.yar#L100-L117"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "076d4ac69f6bc29975b22e19d429c25ef357443ec8fcaf5165e0a8069112af74"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c8374ff2a85f90f153bcd2451109a65d3757eb7cef21abef69f7c6a4f214b051"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 84 C0 75 1E 8B 44 24 2C 89 7C 24 04 89 34 24 89 44 24 0C 8B 44 }

	condition:
		all of them
}