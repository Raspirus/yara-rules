rule SIGNATURE_BASE_APT_RANCOR_PLAINTEE_Variant : FILE
{
	meta:
		description = "Detects PLAINTEE malware"
		author = "Florian Roth (Nextron Systems)"
		id = "f5b68079-0517-504d-a45f-f6ced532db82"
		date = "2018-06-26"
		modified = "2023-12-05"
		reference = "https://researchcenter.paloaltonetworks.com/2018/06/unit42-rancor-targeted-attacks-south-east-asia-using-plaintee-ddkong-malware-families/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_rancor.yar#L30-L49"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d22aa91d0f66dbb85b79c0f121f0508135bf817929d81f3ff0b3fdf223ba53ec"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "6aad1408a72e7adc88c2e60631a6eee3d77f18a70e4eee868623588612efdd31"
		hash2 = "bcd37f1d625772c162350e5383903fe8dbed341ebf0dc38035be5078624c039e"

	strings:
		$s1 = "payload.dat" fullword ascii
		$s3 = "temp_microsoft_test.txt" fullword ascii
		$s4 = "reg add %s /v %s /t REG_SZ /d \"%s\"" fullword ascii
		$s6 = "%s %s,helloworld2" fullword ascii
		$s9 = "%s \\\"%s\\\",helloworld" fullword ascii
		$s16 = "recv plugin type %s size:%d" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 3 of them
}