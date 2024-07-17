rule SIGNATURE_BASE_HKTL_Lazagne_Passworddumper_Dec18_1 : FILE
{
	meta:
		description = "Detects password dumper Lazagne often used by middle eastern threat groups"
		author = "Florian Roth (Nextron Systems)"
		id = "bae48a4d-33b6-55b9-abf5-daf87e5da9e9"
		date = "2018-12-11"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/blogs/threat-intelligence/seedworm-espionage-group"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4545-L4565"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "887c8e91942076395dc7575d5cbd926e7e0971a759daf719983dd918d9babad3"
		score = 85
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "1205f5845035e3ee30f5a1ced5500d8345246ef4900bcb4ba67ef72c0f79966c"
		hash2 = "884e991d2066163e02472ea82d89b64e252537b28c58ad57d9d648b969de6a63"
		hash3 = "bf8f30031769aa880cdbe22bc0be32691d9f7913af75a5b68f8426d4f0c7be50"

	strings:
		$s1 = "softwares.opera(" ascii
		$s2 = "softwares.mozilla(" ascii
		$s3 = "config.dico(" ascii
		$s4 = "softwares.chrome(" ascii
		$s5 = "softwares.outlook(" ascii

	condition:
		uint16(0)==0x5a4d and filesize <17000KB and 1 of them
}