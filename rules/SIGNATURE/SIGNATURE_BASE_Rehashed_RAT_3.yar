rule SIGNATURE_BASE_Rehashed_RAT_3 : FILE
{
	meta:
		description = "Detects malware from Rehashed RAT incident"
		author = "Florian Roth (Nextron Systems)"
		id = "59871be1-295f-54ee-ab4d-4f9e5fdc2935"
		date = "2017-09-08"
		modified = "2022-12-21"
		reference = "https://blog.fortinet.com/2017/09/05/rehashed-rat-used-in-apt-campaign-against-vietnamese-organizations"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_rehashed_rat.yar#L69-L85"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "46f21f11959f863c85a1cfac74a28ba86d5b9789fea5a428168d157c13cce022"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "9cebae97a067cd7c2be50d7fd8afe5e9cf935c11914a1ab5ff59e91c1e7e5fc4"

	strings:
		$x1 = "\\BisonNewHNStubDll\\Release\\Goopdate.pdb" ascii
		$s2 = "psisrndrx.ebd" fullword wide
		$s3 = "pbad exception" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and (1 of ($x*) or 2 of them )
}