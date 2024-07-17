rule SIGNATURE_BASE_MAL_Burningumbrella_Sample_14 : FILE
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		author = "Florian Roth (Nextron Systems)"
		id = "a2b3a4bb-ca60-5dc2-8124-17e654e326b8"
		date = "2018-05-04"
		modified = "2023-12-05"
		reference = "https://401trg.pw/burning-umbrella/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti_burning_umbrella.yar#L217-L231"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "37515683804e9aa076a588048713b420501b2aaf6b8617501ef550484abd1c03"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "388ef4b4e12a04eab451bd6393860b8d12948f2bce12e5c9022996a9167f4972"

	strings:
		$s1 = "C:\\tmp\\Google_updata.exe" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <40KB and 1 of them
}