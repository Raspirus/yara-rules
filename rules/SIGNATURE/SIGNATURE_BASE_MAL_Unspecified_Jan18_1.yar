rule SIGNATURE_BASE_MAL_Unspecified_Jan18_1 : FILE
{
	meta:
		description = "Detects unspecified malware sample"
		author = "Florian Roth (Nextron Systems)"
		id = "f3187c60-8fff-54de-9918-2fb2301f2d92"
		date = "2018-01-19"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_malware_generic.yar#L91-L110"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "cd4f7247473e04c348b49970ee3a6fd01415f005ac6dc7a79fbf937a693a80f4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f87879b29ff83616e9c9044bd5fb847cf5d2efdd2f01fc284d1a6ce7d464a417"

	strings:
		$s1 = "User-Agent: Mozilla/4.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword ascii
		$s2 = "ping 192.0.2.2 -n 1 -w %d >nul 2>&1" fullword ascii
		$s3 = "[Log Started] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword ascii
		$s4 = "start /b \"\" cmd /c del \"%%~f0\"&exit /b" fullword ascii
		$s5 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword ascii
		$s6 = "%s\\%s.bat" fullword ascii
		$s7 = "DEL /s \"%s\" >nul 2>&1" fullword ascii

	condition:
		filesize <300KB and 2 of them
}