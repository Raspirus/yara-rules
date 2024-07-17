import "pe"


rule SIGNATURE_BASE_MAL_Burningumbrella_Sample_1 : FILE
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		author = "Florian Roth (Nextron Systems)"
		id = "9f8a6831-172b-5310-9763-43657b79b91d"
		date = "2018-05-04"
		modified = "2023-12-05"
		reference = "https://401trg.pw/burning-umbrella/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti_burning_umbrella.yar#L13-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d8ed432fea930eb9b4d695a4a68b833f4324fe0bbea3f0ccac2fe5934bfa1c22"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "fcfe8fcf054bd8b19226d592617425e320e4a5bb4798807d6f067c39dfc6d1ff"

	strings:
		$s1 = { 40 00 00 E0 75 68 66 61 6F 68 6C 79 }
		$s2 = { 40 00 00 E0 64 6A 7A 66 63 6D 77 62 }

	condition:
		uint16(0)==0x5a4d and filesize <4000KB and (pe.imphash()=="baa93d47220682c04d92f7797d9224ce" and $s1 in (0..1024) and $s2 in (0..1024))
}