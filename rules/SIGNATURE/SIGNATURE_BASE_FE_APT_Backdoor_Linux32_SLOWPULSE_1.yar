rule SIGNATURE_BASE_FE_APT_Backdoor_Linux32_SLOWPULSE_1 : FILE
{
	meta:
		description = "Detects samples mentioned in PulseSecure report"
		author = "Mandiant"
		id = "dd35257f-5b6f-55a6-a709-873ded1f4b72"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_pulsesecure.yar#L227-L244"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "cd09ec795a8f4b6ced003500a44d810f49943514e2f92c81ab96c33e1c0fbd68"
		logic_hash = "c1d92ea4ed8e5934c8356e1e52092935c53a138e454026737448f7f523ea06be"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$sb1 = {FC b9 [4] e8 00 00 00 00 5? 8d b? [4] 8b}
		$sb2 = {f3 a6 0f 85 [4] b8 03 00 00 00 5? 5? 5?}
		$sb3 = {9c 60 e8 00 00 00 00 5? 8d [5] 85 ?? 0f 8?}
		$sb4 = {89 13 8b 51 04 89 53 04 8b 51 08 89 53 08}
		$sb5 = {8d [5] b9 [4] f3 a6 0f 8?}

	condition:
		(( uint32(0)==0x464c457f) and ( uint8(4)==1)) and all of them
}