
rule ELASTIC_Windows_Trojan_Sliver_46525B49 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Sliver (Windows.Trojan.Sliver)"
		author = "Elastic Security"
		id = "46525b49-f426-4ecb-9bd6-36752f0461e9"
		date = "2023-05-09"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Sliver.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ecce5071c28940a1098aca3124b3f82e0630c4453f4f32e1b91576aac357ac9c"
		logic_hash = "6e61d82b191a740882bcfeac2f2cf337e19ace7b05784ff041b6af2f79ed8809"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "104382f222b754b3de423803ac7be1d6fbdd9cbd11c855774d1ecb1ee73cb6c0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { B6 54 0C 48 0F B6 74 0C 38 31 D6 40 88 74 0C 38 48 FF C1 48 83 }
		$a2 = { 42 18 4C 8B 4A 20 48 8B 52 28 48 39 D9 73 51 48 89 94 24 C0 00 }

	condition:
		all of them
}