rule ELASTIC_Windows_Ransomware_Mespinoza_3Adb59F5 : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Mespinoza (Windows.Ransomware.Mespinoza)"
		author = "Elastic Security"
		id = "3adb59f5-a4af-48f2-8029-874a62b23651"
		date = "2021-08-05"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Mespinoza.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6f3cd5f05ab4f404c78bab92f705c91d967b31a9b06017d910af312fa87ae3d6"
		logic_hash = "28c8ad42a3af70fed274edc9105dae5cef13749d71510561a50428c822464934"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f44a79048427e79d339d3b0ccaeb85ba6731d5548256a2615f32970dcf67578f"
		severity = 90
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Don't try to use backups because it were encrypted too." ascii fullword
		$a2 = "Every byte on any types of your devices was encrypted." ascii fullword
		$a3 = "n.pysa" wide fullword

	condition:
		all of them
}