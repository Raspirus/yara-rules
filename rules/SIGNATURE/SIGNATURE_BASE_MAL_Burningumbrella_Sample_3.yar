rule SIGNATURE_BASE_MAL_Burningumbrella_Sample_3 : FILE
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		author = "Florian Roth (Nextron Systems)"
		id = "b997822a-3f62-51b4-bd96-e780ffe60812"
		date = "2018-05-04"
		modified = "2023-12-05"
		reference = "https://401trg.pw/burning-umbrella/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti_burning_umbrella.yar#L53-L66"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "ad39864eec58b1c655bd3d510faa314702d118cee845da55d189e7252174eafb"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "92efbecc24fbb5690708926b6221b241b10bdfe3dd0375d663b051283d0de30f"

	strings:
		$s1 = "HKEY_CLASSES_ROOT\\Word.Document.8\\shell\\Open\\command" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 1 of them
}