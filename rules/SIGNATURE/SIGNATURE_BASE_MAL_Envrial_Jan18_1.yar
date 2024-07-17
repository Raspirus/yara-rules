
rule SIGNATURE_BASE_MAL_Envrial_Jan18_1 : FILE
{
	meta:
		description = "Detects Encrial credential stealer malware"
		author = "Florian Roth (Nextron Systems)"
		id = "8be5f0d8-013f-5070-9e19-9ac522c88693"
		date = "2018-01-21"
		modified = "2023-12-05"
		reference = "https://twitter.com/malwrhunterteam/status/953313514629853184"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_envrial.yar#L11-L40"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f047bedaac4dd934657b282a2587c55f3087a7cceb1a80becf14e7db3c365e8b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "9ae3aa2c61f7895ba6b1a3f85fbe36c8697287dc7477c5a03d32cf994fdbce85"
		hash2 = "9edd8f0e22340ecc45c5f09e449aa85d196f3f506ff3f44275367df924b95c5d"

	strings:
		$x1 = "/Evrial/master/domen" wide
		$a1 = "\\Opera Software\\Opera Stable\\Login Data" wide
		$a2 = "\\Comodo\\Dragon\\User Data\\Default\\Login Data" wide
		$a3 = "\\Google\\Chrome\\User Data\\Default\\Login Data" wide
		$a4 = "\\Orbitum\\User Data\\Default\\Login Data" wide
		$a5 = "\\Kometa\\User Data\\Default\\Login Data" wide
		$s1 = "dlhosta.exe" fullword wide
		$s2 = "\\passwords.log" wide
		$s3 = "{{ <>h__TransparentIdentifier1 = {0}, Password = {1} }}" fullword wide
		$s4 = "files/upload.php?user={0}&hwid={1}" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <900KB and (1 of ($x*) or 3 of them or 2 of ($s*))
}