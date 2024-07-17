import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


rule SIGNATURE_BASE_Passwordspro : FILE
{
	meta:
		description = "Auto-generated rule - file PasswordsPro.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "c749f883-364e-5f65-9eb8-3dcd74495f7c"
		date = "2017-08-27"
		modified = "2023-12-05"
		reference = "PasswordPro"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L3924-L3942"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "24887c3a7e4997c9a4e5d3317a5684b0eca7ccc0ffb213660dd9b37bb220f514"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "5b3d6654e6d9dc49ee1136c0c8e8122cb0d284562447abfdc05dfe38c79f95bf"

	strings:
		$s1 = "No users marked for attack or all marked users already have passwords found!" fullword ascii
		$s2 = "%s\\PasswordsPro.ini.Dictionaries(%d)" fullword ascii
		$s3 = "Passwords processed since attack start:" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and 1 of them )
}