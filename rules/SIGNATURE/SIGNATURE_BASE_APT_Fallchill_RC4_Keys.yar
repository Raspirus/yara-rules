import "pe"


rule SIGNATURE_BASE_APT_Fallchill_RC4_Keys : FILE
{
	meta:
		description = "Detects FallChill RC4 keys"
		author = "Florian Roth (Nextron Systems)"
		id = "ead7d84c-91aa-58b0-af3b-1211b0bde864"
		date = "2018-08-21"
		modified = "2023-12-05"
		reference = "https://securelist.com/operation-applejeus/87553/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_lazarus_applejeus.yar#L84-L100"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "59861618dba256996d7bbcd94a6efccdb64589fc75086bfe7d980fa51761ef97"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$cod0 = { c7 ?? ?? da e1 61 ff
                c7 ?? ?? 0c 27 95 87
                c7 ?? ?? 17 57 a4 d6
                c7 ?? ?? ea e3 82 2b }

	condition:
		uint16(0)==0x5a4d and 1 of them
}