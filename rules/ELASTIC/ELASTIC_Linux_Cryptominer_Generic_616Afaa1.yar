
rule ELASTIC_Linux_Cryptominer_Generic_616Afaa1 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "616afaa1-7679-4198-9e80-c3f044b3c07d"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L401-L419"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0901672d2688660baa26fdaac05082c9e199c06337871d2ae40f369f5d575f71"
		logic_hash = "53a309a6a274558e4ae8cfa8f3e258f23dc9ceafab3be46351c00d24f5d790ec"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fd6afad9f318ce00b0f0f8be3a431a2c7b4395dd69f82328f4555b3715a8b298"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 4B 04 31 C0 41 8B 14 07 89 14 01 48 83 C0 04 48 83 F8 14 75 EF 4C 8D 74 }

	condition:
		all of them
}