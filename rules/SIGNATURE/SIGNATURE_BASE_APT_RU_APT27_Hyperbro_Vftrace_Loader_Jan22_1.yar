rule SIGNATURE_BASE_APT_RU_APT27_Hyperbro_Vftrace_Loader_Jan22_1 : FILE
{
	meta:
		description = "Yara rule to detect first Hyperbro Loader Stage, often called vftrace.dll. Detects decoding function."
		author = "Bundesamt fuer Verfassungsschutz (modified by Florian Roth)"
		id = "b049e163-2694-5fb9-a3a3-98cc77bcd0ca"
		date = "2022-01-14"
		modified = "2023-12-05"
		reference = "https://www.verfassungsschutz.de/SharedDocs/publikationen/DE/cyberabwehr/2022-01-bfv-cyber-brief.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt27_hyperbro.yar#L3-L19"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d8785ea937891636bea5ed8128de44fa6084a1a48800c1586739c5ca9e4c43bd"
		score = 75
		quality = 85
		tags = "FILE"
		sharing = "TLP:WHITE"
		hash1 = "333B52C2CFAC56B86EE9D54AEF4F0FF4144528917BC1AA1FE1613EFC2318339A"

	strings:
		$decoder_routine = { 8A ?? 41 10 00 00 8B ?? 28 ?? ?? 4? 3B ?? 72 ?? }

	condition:
		uint16(0)==0x5a4d and filesize <5MB and $decoder_routine and pe.exports("D_C_Support_SetD_File")
}