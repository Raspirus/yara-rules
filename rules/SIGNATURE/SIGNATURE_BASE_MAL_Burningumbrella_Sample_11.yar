rule SIGNATURE_BASE_MAL_Burningumbrella_Sample_11 : FILE
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		author = "Florian Roth (Nextron Systems)"
		id = "9762c68c-4d69-5d38-aaf4-0048e7404147"
		date = "2018-05-04"
		modified = "2023-12-05"
		reference = "https://401trg.pw/burning-umbrella/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti_burning_umbrella.yar#L165-L178"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "847681b3e9d4fc38c483663f5a7e16e7f8f95cfa77728d7316edbe6fbf5fe2c1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "278e9d130678615d0fee4d7dd432f0dda6d52b0719649ee58cbdca097e997c3f"

	strings:
		$s1 = "Resume.app/Contents/Java/Resume.jarPK" fullword ascii

	condition:
		uint16(0)==0x4b50 and filesize <700KB and 1 of them
}