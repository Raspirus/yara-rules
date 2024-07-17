
rule SIGNATURE_BASE_M_APT_VIRTUALPITA_3 : FILE
{
	meta:
		description = "Finds opcodes from 409dd8 to 409e46 in fe34b7c071d96dac498b72a4a07cb246 to set the HISTFILE environment variable to 'F' with a putenv() after loading each character individually."
		author = "Mandiant"
		id = "29ea2db0-4ab2-5e9c-8d42-7590ceabf99a"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_unc3886_virtualpita.yar#L30-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "fe34b7c071d96dac498b72a4a07cb246"
		logic_hash = "6f44d516b3cbe54542ae0991aad49274fc4728570e9498b319fc98840ceb7d7d"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x = {4? 8b 4? ?? c6 00 48 4? 8b 4? ?? 4? 83 c0 05 c6 00 49 4? 8b 4? ?? 4? 83 c0 01 c6 00 49 4? 8b 4? ?? 4? 83 c0 06 c6 00 4c 4? 8b 4? ?? 4? 83 c0 02 c6 00 53 4? 8b 4? ?? 4? 83 c0 07 c6 00 45 4? 8b 4? ?? 4? 83 c0 03 c6 00 54 4? 8b 4? ?? 4? 83 c0 08 c6 00 3d 4? 8b 4? ?? 4? 83 c0 04 c6 00 46 4? 8b 4? ?? 4? 83 c0 09 c6 00 00 4? 8b 7? ?? e8}

	condition:
		uint32(0)==0x464c457f and all of them
}