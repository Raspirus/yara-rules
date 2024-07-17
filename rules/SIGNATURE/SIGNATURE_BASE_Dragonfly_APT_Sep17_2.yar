rule SIGNATURE_BASE_Dragonfly_APT_Sep17_2 : FILE
{
	meta:
		description = "Detects malware from DrqgonFly APT report"
		author = "Florian Roth (Nextron Systems)"
		id = "e64f121d-a628-54b5-88f3-96eea388c155"
		date = "2017-09-12"
		modified = "2023-01-06"
		reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_dragonfly.yar#L46-L66"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "433711dd15c8d1044b381046747194e47402288df06da6bbc61055dc9c90f52a"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "178348c14324bc0a3e57559a01a6ae6aa0cb4013aabbe324b51f906dcf5d537e"

	strings:
		$s1 = "\\AppData\\Roaming\\Opera Software\\Opera Stable\\Login Data" wide
		$s2 = "C:\\Users\\Public\\Log.txt" fullword wide
		$s3 = "SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins" fullword wide
		$s4 = "***************** Mozilla Firefox ****************" fullword wide
		$s5 = "********************** Opera *********************" fullword wide
		$s6 = "\\AppData\\Local\\Microsoft\\Credentials\\" wide
		$s7 = "\\Appdata\\Local\\Google\\Chrome\\User Data\\Default\\" wide
		$s8 = "**************** Internet Explorer ***************" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <3000KB and 3 of them )
}