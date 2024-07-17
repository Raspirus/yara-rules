rule SIGNATURE_BASE_Nanocore_RAT_Feb18_2 : FILE
{
	meta:
		description = "Detects Nanocore RAT"
		author = "Florian Roth (Nextron Systems)"
		id = "83a8ad4d-0bef-5ba2-aa10-eac5601f2c7b"
		date = "2018-02-19"
		modified = "2023-12-05"
		reference = "Internal Research - T2T"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_nanocore_rat.yar#L117-L137"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c104e431a4ecc0d18d7eb74e7a55d32bf8978ee922637d48f3f6a9466a0f5b1a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "377ef8febfd8df1a57a7966043ff0c7b8f3973c2cf666136e6c04080bbf9881a"

	strings:
		$s1 = "ResManagerRunnable" fullword ascii
		$s2 = "TransformRunnable" fullword ascii
		$s3 = "MethodInfoRunnable" fullword ascii
		$s4 = "ResRunnable" fullword ascii
		$s5 = "RunRunnable" fullword ascii
		$s6 = "AsmRunnable" fullword ascii
		$s7 = "ReadRunnable" fullword ascii
		$s8 = "ExitRunnable" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of them
}