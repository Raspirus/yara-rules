
rule SIGNATURE_BASE_FE_APT_Trojan_Linux32_LOCKPICK_1 : FILE
{
	meta:
		description = "Detects samples mentioned in PulseSecure report"
		author = "Mandiant"
		id = "00c09378-25a0-55f1-8d93-7b22d98bd8c2"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_pulsesecure.yar#L66-L80"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "e8bfd3f5a2806104316902bbe1195ee8"
		logic_hash = "1623c2dc63fe7d595069a024b715bbca267ec1c9400afcadc377ae58afb81a2a"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$sb1 = { 83 ?? 63 0F 84 [4] 8B 45 ?? 83 ?? 01 89 ?? 24 89 44 24 04 E8 [4] 85 C0 }
		$sb2 = { 83 [2] 63 74 ?? 89 ?? 24 04 89 ?? 24 E8 [4] 83 [2] 01 85 C0 0F [5] EB 00 8B ?? 04 83 F8 02 7? ?? 83 E8 01 C1 E0 02 83 C0 00 89 44 24 08 8D 83 [4] 89 44 24 04 8B ?? 89 04 24 E8 }

	condition:
		(( uint32(0)==0x464c457f) and ( uint8(4)==1)) and (@sb1[1]<@sb2[1])
}