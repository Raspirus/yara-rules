
rule ELASTIC_Linux_Ransomware_Clop_728Cf32A : FILE MEMORY
{
	meta:
		description = "Detects Linux Ransomware Clop (Linux.Ransomware.Clop)"
		author = "Elastic Security"
		id = "728cf32a-94c1-4979-b092-6851649946be"
		date = "2023-07-27"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Ransomware_Clop.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "09d6dab9b70a74f61c41eaa485b37de9a40c86b6d2eae7413db11b4e6a8256ef"
		logic_hash = "31c2fdfcfc46ad1dd69489536172937b9771d8505f36c7bd8dc796f40a2fe4d2"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "86644f9f1e9f0b69896cd05ae1442a3b99483cc0ff15773c0c3403e59b6d5c97"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "CONTACT US BY EMAIL:"
		$a2 = "OR WRITE TO THE CHAT AT->"
		$a3 = "(use TOR browser)"
		$a4 = ".onion/"

	condition:
		3 of them
}