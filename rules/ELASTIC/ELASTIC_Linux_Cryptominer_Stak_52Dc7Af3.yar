
rule ELASTIC_Linux_Cryptominer_Stak_52Dc7Af3 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Stak (Linux.Cryptominer.Stak)"
		author = "Elastic Security"
		id = "52dc7af3-a742-4307-a5ae-c929fede1cc4"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Stak.yar#L60-L78"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a9c14b51f95d0c368bf90fb10e7d821a2fbcc79df32fd9f068a7fc053cbd7e83"
		logic_hash = "81998164f517b6f1ef72b10227cfff86aa8bbd2b4e2668f946c8ed59696ae74d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "330262703d3fcdd8b2c217db552f07e19f5df4d6bf115bfa291bb1c7f802ad97"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F9 48 89 D3 4D 8B 74 24 20 48 8D 41 01 4C 29 FB 4C 8D 6B 10 48 }

	condition:
		all of them
}