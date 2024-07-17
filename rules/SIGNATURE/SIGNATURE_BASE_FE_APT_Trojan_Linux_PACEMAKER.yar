rule SIGNATURE_BASE_FE_APT_Trojan_Linux_PACEMAKER : FILE
{
	meta:
		description = "Detects samples mentioned in PulseSecure report"
		author = "Mandiant"
		id = "5a20260a-5389-57da-956c-97063fed5015"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_pulsesecure.yar#L99-L115"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "d7881c4de4d57828f7e1cab15687274b"
		logic_hash = "cf83024cbbd500a301ac3c859b680cd79acabc232ea6f42c23fe9f8918a8d914"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "\x00Name:%s || Pwd:%s || AuthNum:%s\x0a\x00"
		$s2 = "\x00/proc/%d/mem\x00"
		$s3 = "\x00/proc/%s/maps\x00"
		$s4 = "\x00/proc/%s/cmdline\x00"

	condition:
		( uint32(0)==0x464c457f) and all of them
}