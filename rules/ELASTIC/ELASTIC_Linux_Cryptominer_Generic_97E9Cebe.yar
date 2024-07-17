
rule ELASTIC_Linux_Cryptominer_Generic_97E9Cebe : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "97e9cebe-d30b-49f6-95f4-fd551e7a42e4"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L241-L259"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b4ff62d92bd4d423379f26b37530776b3f4d927cc8a22bd9504ef6f457de4b7a"
		logic_hash = "8aad31db2646fb9971b9af886e30f6c5a62a9c7de86cb9dc9e1341ac3b7762eb"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "61bef39d174d97897ac0820b624b1afbfe73206208db420ae40269967213ebed"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 8B 04 25 28 00 00 00 48 89 44 24 58 31 C0 49 83 FF 3F 48 89 74 }

	condition:
		all of them
}