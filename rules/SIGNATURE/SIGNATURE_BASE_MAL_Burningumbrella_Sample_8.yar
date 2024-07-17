rule SIGNATURE_BASE_MAL_Burningumbrella_Sample_8 : FILE
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		author = "Florian Roth (Nextron Systems)"
		id = "1b89d5a1-1425-5cb7-b429-563769bc0943"
		date = "2018-05-04"
		modified = "2023-12-05"
		reference = "https://401trg.pw/burning-umbrella/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti_burning_umbrella.yar#L132-L145"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1a42667463ff006b155c93b8986ab75441ba00d0c3c146c2d4c6929250627d8d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "73270fe9bca94fead1b5b38ddf69fae6a42e574e3150d3e3ab369f5d37d93d88"

	strings:
		$s1 = "cmd /c open %s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 1 of them
}