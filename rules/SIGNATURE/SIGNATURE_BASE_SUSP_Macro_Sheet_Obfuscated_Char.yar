
rule SIGNATURE_BASE_SUSP_Macro_Sheet_Obfuscated_Char : FILE
{
	meta:
		description = "Finding hidden/very-hidden macros with many CHAR functions"
		author = "DissectMalware"
		id = "791e9bba-3e4e-5efd-a800-a612c6f92cfb"
		date = "2020-04-07"
		modified = "2023-12-05"
		reference = "https://twitter.com/DissectMalware/status/1247595433305800706"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_susp_office_dropper.yar#L122-L139"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0953d1f916df570cb3d053bf4fdac196bdbd806df4b6c0a982ed9949a3676e6c"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "0e9ec7a974b87f4c16c842e648dd212f80349eecb4e636087770bc1748206c3b"

	strings:
		$ole_marker = {D0 CF 11 E0 A1 B1 1A E1}
		$s1 = "Excel" fullword ascii
		$macro_sheet_h1 = {85 00 ?? ?? ?? ?? ?? ?? 01 01}
		$macro_sheet_h2 = {85 00 ?? ?? ?? ?? ?? ?? 02 01}
		$char_func = {06 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 1E 3D  00 41 6F 00}

	condition:
		$ole_marker at 0 and 1 of ($macro_sheet_h*) and #char_func>10 and $s1
}