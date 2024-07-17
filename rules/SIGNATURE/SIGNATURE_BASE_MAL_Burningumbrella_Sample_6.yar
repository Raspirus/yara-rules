rule SIGNATURE_BASE_MAL_Burningumbrella_Sample_6 : FILE
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		author = "Florian Roth (Nextron Systems)"
		id = "7198a734-fd54-5cb5-9966-b91796a415c7"
		date = "2018-05-04"
		modified = "2023-12-05"
		reference = "https://401trg.pw/burning-umbrella/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti_burning_umbrella.yar#L101-L115"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ee671bc09cc0c84c9817ed800f1416a75f18a70fd2cf6a7e9f063fffa01fa003"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "49ef2b98b414c321bcdbab107b8fa71a537958fe1e05ae62aaa01fe7773c3b4b"

	strings:
		$s1 = "ExecuteFile=\"hidcon:nowait:\\\"Word\\\\r.bat\\\"\"" fullword ascii
		$s2 = "InstallPath=\"%Appdata%\\\\Microsoft\"" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 1 of them
}