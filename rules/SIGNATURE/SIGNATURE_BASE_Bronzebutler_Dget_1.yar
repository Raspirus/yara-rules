rule SIGNATURE_BASE_Bronzebutler_Dget_1 : FILE
{
	meta:
		description = "Detects malware / hacktool sample from Bronze Butler incident"
		author = "Florian Roth (Nextron Systems)"
		id = "d60fcc9f-0f17-5871-9e8e-71d26e2f46bc"
		date = "2017-10-14"
		modified = "2023-12-05"
		reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_bronze_butler.yar#L80-L93"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2d5537f581039fa4561950402a34cbd9abd54c167d659fbbe74f1cb83217e3fb"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "bd81521445639aaa5e3bcb5ece94f73feda3a91880a34a01f92639f8640251d6"

	strings:
		$s2 = "DGet Tool Made by XZ" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <10KB and 1 of them )
}