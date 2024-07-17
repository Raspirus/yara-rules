
rule SIGNATURE_BASE_Hatman_Dividers_PRIVATE : HATMAN
{
	meta:
		description = "No description has been set in the source file - Signature Base"
		author = "Florian Roth"
		id = "1612a184-e06c-5c1b-987d-04e330e17ed0"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hatman.yar#L38-L44"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "92ec47ea81b78ec9b05f5c17164daaef7112c8590b4443f70cf3bf2efd108e1f"
		score = 75
		quality = 85
		tags = "HATMAN"

	strings:
		$div1 = { 9a 78 56 00 }
		$div2 = { 34 12 00 00 }

	condition:
		$div1 and $div2
}