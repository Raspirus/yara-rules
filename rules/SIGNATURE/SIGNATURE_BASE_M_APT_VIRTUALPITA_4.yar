rule SIGNATURE_BASE_M_APT_VIRTUALPITA_4 : FILE
{
	meta:
		description = "Finds opcodes from 401f1c to 401f4f in fe34b7c071d96dac498b72a4a07cb246 to decode text with multiple XORs"
		author = "Mandiant"
		id = "58d4db75-fcd5-50c2-93ba-a8a4718ac0f6"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_unc3886_virtualpita.yar#L43-L55"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "fe34b7c071d96dac498b72a4a07cb246"
		logic_hash = "aaf2ff682c619d2a254fe069d477654a161658db6315239f1b956141b6a72c01"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x = {4? 8b 4? ?? 4? 83 c1 30 4? 8b 4? ?? 4? 8b 10 8b 4? ?? 4? 98 4? 8b 04 ?? ?? ?? ?? ?? 4? 31 c2 4? 8b 4? ?? 4? 83 c0 28 4? 8b 00 4? c1 e8 10 0f b6 c0 4? 98 4? 8b 04}

	condition:
		uint32(0)==0x464c457f and all of them
}