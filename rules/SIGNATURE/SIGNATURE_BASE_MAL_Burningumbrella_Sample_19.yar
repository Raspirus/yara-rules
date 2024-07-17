rule SIGNATURE_BASE_MAL_Burningumbrella_Sample_19 : FILE
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		author = "Florian Roth (Nextron Systems)"
		id = "8ab55e80-5d28-5a5f-a1cc-725ba6720e4b"
		date = "2018-05-04"
		modified = "2023-12-05"
		reference = "https://401trg.pw/burning-umbrella/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti_burning_umbrella.yar#L315-L332"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "218c16d1b67e3e80dc7fdaf67a869e92b39744cb336e70761ac960da36c00372"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "05e2912f2a593ba16a5a094d319d96715cbecf025bf88bb0293caaf6beb8bc20"
		hash2 = "e7bbdb275773f43c8e0610ad75cfe48739e0a2414c948de66ce042016eae0b2e"

	strings:
		$s1 = "Cryption.dll" fullword ascii
		$s2 = "tran.exe" fullword ascii
		$s3 = "Kernel.dll" fullword ascii
		$s4 = "Now ready to get the file %s!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 3 of them
}