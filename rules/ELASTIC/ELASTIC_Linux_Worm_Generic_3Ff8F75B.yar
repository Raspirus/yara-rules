
rule ELASTIC_Linux_Worm_Generic_3Ff8F75B : FILE MEMORY
{
	meta:
		description = "Detects Linux Worm Generic (Linux.Worm.Generic)"
		author = "Elastic Security"
		id = "3ff8f75b-619e-4090-8ea4-aedc8bdf61a4"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Worm_Generic.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "991175a96b719982f3a846df4a66161a02225c21b12a879e233e19124e90bd35"
		logic_hash = "798e98f286201f1cda18bf1bf433826cf8a949b584f016b24a684425069d1024"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "011f0cd72ebb428775305c84eac69c5ff4800de6e1d8b4d2110d5445b1aae10f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 3A DF FE 00 66 0F 73 FB 04 66 0F 6F D3 66 0F EF D9 66 0F 6F EE 66 0F 70 }

	condition:
		all of them
}