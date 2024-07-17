rule SIGNATURE_BASE_Bronzebutler_Daserf_Delphi_1 : FILE
{
	meta:
		description = "Detects malware / hacktool sample from Bronze Butler incident"
		author = "Florian Roth (Nextron Systems)"
		id = "88372e62-3bba-58dc-825c-f35533e42825"
		date = "2017-10-14"
		modified = "2023-12-05"
		reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_bronze_butler.yar#L13-L36"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "6034a6746a5bd762d869ad2e791d80aca8a1251afa9386d6b657f23092c6fc42"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "89a80ca92600af64eb9c32cab4e936c7d675cf815424d72438973e2d6788ef64"
		hash2 = "b1bd03cd12638f44d9ace271f65645e7f9b707f86e9bcf790e0e5a96b755556b"
		hash3 = "22e1965154bdb91dd281f0e86c8be96bf1f9a1e5fe93c60a1d30b79c0c0f0d43"

	strings:
		$s1 = "Services.exe" fullword ascii
		$s2 = "Mozilla/4.0 (compatible; MSIE 11.0; Windows NT 6.1; SV1)" fullword ascii
		$s3 = "l32.dll" fullword ascii
		$s4 = "tProcess:" fullword ascii
		$s5 = " InjectPr" ascii
		$s6 = "Write$Error creating variant or safe array\x1fInvalid argument to time encode" fullword wide
		$s7 = "on\\run /v " fullword ascii
		$s8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\run" fullword ascii
		$s9 = "ms1ng2d3d2.exe" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and 3 of them )
}