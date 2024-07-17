
rule R3C0NST_Aplib_Decompression : FILE
{
	meta:
		description = "Detects aPLib decompression code often used in malware"
		author = "@r3c0nst"
		id = "f45c73f5-d316-5fea-a8c4-fd930733415f"
		date = "2021-03-24"
		modified = "2021-03-25"
		reference = "https://ibsensoftware.com/files/aPLib-1.1.1.zip"
		source_url = "https://github.com/fboldewin/YARA-rules//blob/54e9e6899b258b72074b2b4db6909257683240c2/aPLib_decompression.yar#L1-L16"
		license_url = "N/A"
		logic_hash = "1150701724fdb487ebe8fb959afd12fff37a8e9137cb94e78e976a2566ec5fa4"
		score = 75
		quality = 90
		tags = "FILE"

	strings:
		$pattern1 = { FC B2 80 31 DB A4 B3 02 }
		$pattern2 = { AC D1 E8 74 ?? 11 C9 EB }
		$pattern3 = { 73 0A 80 FC 05 73 ?? 83 F8 7F 77 }

	condition:
		filesize <10MB and all of them
}