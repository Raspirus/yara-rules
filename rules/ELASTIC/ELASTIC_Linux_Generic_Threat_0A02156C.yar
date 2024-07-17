rule ELASTIC_Linux_Generic_Threat_0A02156C : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "0a02156c-2958-44c5-9dbd-a70d528e507d"
		date = "2024-02-01"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L614-L633"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f23d4b1fd10e3cdd5499a12f426e72cdf0a098617e6b178401441f249836371e"
		logic_hash = "3ceea812f0252ec703a92482ce7a3ef0aa65bad149df2aa0107e07a45490b8f1"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "aa7a34e72e03b70f2f73ae319e2cc9866fbf2eddd4e6a8a2835f9b7c400831cd"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 72 65 71 75 69 72 65 73 5F 6E 75 6C 6C 5F 70 61 67 65 }
		$a2 = { 67 65 74 5F 65 78 70 6C 6F 69 74 5F 73 74 61 74 65 5F 70 74 72 }

	condition:
		all of them
}