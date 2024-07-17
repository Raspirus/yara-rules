rule SIGNATURE_BASE_FE_APT_Trojan_Linux32_PACEMAKER : FILE
{
	meta:
		description = "Detects samples mentioned in PulseSecure report"
		author = "Mandiant"
		id = "459e26f1-4ea9-56dd-ad71-0ed2c7499aea"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_pulsesecure.yar#L81-L98"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "d7881c4de4d57828f7e1cab15687274b"
		logic_hash = "f3f89744ce558179f36da3b412ba4afb3798684e6d976ef59de565b5a3323ad6"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "\x00/proc/%d/mem\x00"
		$s2 = "\x00/proc/%s/maps\x00"
		$s3 = "\x00/proc/%s/cmdline\x00"
		$sb1 = { C7 44 24 08 10 00 00 00 C7 44 24 04 00 00 00 00 8D 45 E0 89 04 24 E8 [4] 8B 45 F4 83 C0 0B C7 44 24 08 10 00 00 00 89 44 24 04 8D 45 E0 89 04 24 E8 [4] 8D 45 E0 89 04 24 E8 [4] 85 C0 74 ?? 8D 45 E0 89 04 24 E8 [4] 85 C0 74 ?? 8D 45 E0 89 04 24 E8 [4] EB }
		$sb2 = { 8B 95 [4] B8 [4] 8D 8D [4] 89 4C 24 10 8D 8D [4] 89 4C 24 0C 89 54 24 08 89 44 24 04 8D 85 [4] 89 04 24 E8 [4] C7 44 24 08 02 00 00 00 C7 44 24 04 00 00 00 00 8B 45 ?? 89 04 24 E8 [4] 89 45 ?? 8D 85 [4] 89 04 24 E8 [4] 89 44 24 08 8D 85 [4] 89 44 24 04 8B 45 ?? 89 04 24 E8 [4] 8B 45 ?? 89 45 ?? C7 45 ?? 00 00 00 00 [0-16] 83 45 ?? 01 8B 45 ?? 3B 45 0C }

	condition:
		(( uint32(0)==0x464c457f) and ( uint8(4)==1)) and all of them
}