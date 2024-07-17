rule SIGNATURE_BASE_APT_NK_Babyshark_Kimjoingrat_Apr19_1 : FILE
{
	meta:
		description = "Detects BabyShark KimJongRAT"
		author = "Florian Roth (Nextron Systems)"
		id = "c6bd1e1a-68f2-5a2d-a159-b16ea0d33987"
		date = "2019-04-27"
		modified = "2023-12-05"
		reference = "https://unit42.paloaltonetworks.com/babyshark-malware-part-two-attacks-continue-using-kimjongrat-and-pcrat/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_babyshark.yar#L29-L53"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3fec0f21e299e09ae9734f256edbbca81a53f860b42e99a78b07d344552f1062"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "d50a0980da6297b8e4cec5db0a8773635cee74ac6f5c1ff18197dfba549f6712"

	strings:
		$x1 = "%s\\Microsoft\\ttmp.log" fullword wide
		$a1 = "logins.json" fullword ascii
		$s1 = "https://www.google.com/accounts/servicelogin" fullword ascii
		$s2 = "https://login.yahoo.com/config/login" fullword ascii
		$s3 = "SELECT id, hostname, httpRealm, formSubmitURL, usernameField, passwordField, encryptedUsername, encryptedPassword FROM moz_login" ascii
		$s4 = "\\mozsqlite3.dll" ascii
		$s5 = "SMTP Password" fullword ascii
		$s6 = "Yandex\\YandexBrowser\\User Data\\Default\\Login Data" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and (1 of ($x*) or ($a1 and 3 of ($s*)))
}