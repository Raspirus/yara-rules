import "pe"


rule SIGNATURE_BASE_Xtreme_Sep17_2 : FILE
{
	meta:
		description = "Detects XTREME sample analyzed in September 2017"
		author = "Florian Roth (Nextron Systems)"
		id = "b4878e80-54dc-5a16-9129-ddf2b1a5d287"
		date = "2017-09-27"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_xtreme_rat.yar#L39-L53"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "cb86167e0267d52b1b7503abd8f5b988296e3cde12453ace529c4e043d2ca69e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f8413827c52a5b073bdff657d6a277fdbfda29d909b4247982f6973424fa2dcc"

	strings:
		$s1 = "Spy24.exe" fullword wide
		$s2 = "Remote Service Application" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <3000KB and all of them )
}