rule HARFANGLAB_Custom_Ateraagent_Operator : FILE
{
	meta:
		description = "Detect Atera Agent configured to certain email addresses, or email domains"
		author = "HarfangLab"
		id = "af0fae1d-2d25-5551-8720-ff1172ff4eea"
		date = "2024-04-17"
		modified = "2024-04-22"
		reference = "TRR240402"
		source_url = "https://github.com/HarfangLab/iocs/blob/911b0f27d123986b25ad00cc0e7d94a52435cb15/TRR240402/trr240402_yara-template.yar#L1-L20"
		license_url = "N/A"
		logic_hash = "71622b61c5f645dd846327b79bf6dddefef458b73a82caa34d086da2ba48cd8c"
		score = 75
		quality = 80
		tags = "FILE"
		context = "file"

	strings:
		$email = "email@domain.tld"
		$s1 = "PREVIOUSFOUNDWIX_UPGRADE_DETECTED"
		$s2 = "INTEGRATORLOGIN"
		$sc1 = { 0A 28 49 99 78 E5 89 8D F4 0A 23 8E B8 A5 52 E8 }
		$sc2 = { 06 7F 60 47 95 66 24 A7 15 99 61 74 3D 81 94 93 }

	condition:
		filesize >1MB and filesize <4MB and ( uint16be(0)==0xD0CF) and @s1<@email and @email<@s2[3] and any of ($sc*)
}