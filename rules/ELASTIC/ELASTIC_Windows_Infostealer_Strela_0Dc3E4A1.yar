
rule ELASTIC_Windows_Infostealer_Strela_0Dc3E4A1 : MEMORY
{
	meta:
		description = "Detects Windows Infostealer Strela (Windows.Infostealer.Strela)"
		author = "Elastic Security"
		id = "0dc3e4a1-13ac-4461-aac9-896f9e30d84b"
		date = "2024-03-25"
		modified = "2024-05-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Infostealer_Strela.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e6991b12e86629b38e178fef129dfda1d454391ffbb236703f8c026d6d55b9a1"
		logic_hash = "3e4756f817970a5373183b4d0f893edf0b08fe146c79ed83f86d191199c25095"
		score = 75
		quality = 75
		tags = "MEMORY"
		fingerprint = "517b11ee532ecc6beba5a705618e4a25869abb33fd4ba58e1f956fad95e20ac3"
		severity = 100
		arch_context = "x86"
		scan_context = "memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$s1 = "strela" fullword
		$s2 = "/server.php" fullword
		$s3 = "%s%s\\key4.db" fullword
		$s4 = "%s%s\\logins.json" fullword
		$old_pdb = "Projects\\StrelaDLLCompile\\Release\\StrelaDLLCompile.pdb" fullword

	condition:
		all of ($s*) or $old_pdb
}