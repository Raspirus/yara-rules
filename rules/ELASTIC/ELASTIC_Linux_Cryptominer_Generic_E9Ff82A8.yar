
rule ELASTIC_Linux_Cryptominer_Generic_E9Ff82A8 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "e9ff82a8-b8ca-45fb-9738-3ce0c452044f"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L521-L539"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "62ea137e42ce32680066693f02f57a0fb03483f78c365dffcebc1f992bb49c7a"
		logic_hash = "9309aaad6643fa212bb04ce8dc7d24978839fe475f17d36e3b692320563b6fad"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "91e78b1777a0580f25f7796aa6d9bcbe2cbad257576924aecfe513b1e1206915"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { D9 4D 01 CA 4C 89 74 24 D0 4C 8B 74 24 E8 4D 31 D4 49 C1 C4 20 48 C1 }

	condition:
		all of them
}