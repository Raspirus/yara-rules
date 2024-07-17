
rule ELASTIC_Linux_Cryptominer_Generic_37C3F8D3 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "37c3f8d3-9d79-434c-b0e8-252122ebc62a"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "efbddf1020d0845b7a524da357893730981b9ee65a90e54976d7289d46d0ffd4"
		logic_hash = "e7bdd185ea4227b0960c3e677e7d8ac7488d53eaa77efd631be828b2ca079bb8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6ba0bae987db369ec6cdadf685b8c7184e6c916111743f1f2b43ead8d028338c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F0 4C 01 F0 49 8B 75 08 48 01 C3 49 39 F4 74 29 48 89 DA 4C }

	condition:
		all of them
}