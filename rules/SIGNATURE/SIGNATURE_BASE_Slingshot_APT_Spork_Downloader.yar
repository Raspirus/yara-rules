import "pe"


rule SIGNATURE_BASE_Slingshot_APT_Spork_Downloader : FILE
{
	meta:
		description = "Detects malware from Slingshot APT"
		author = "Florian Roth (Nextron Systems)"
		id = "21e02f78-40d8-5b56-b747-3f2a7a692259"
		date = "2018-03-09"
		modified = "2023-12-05"
		reference = "https://securelist.com/apt-slingshot/84312/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_slingshot.yar#L11-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5dac11c595d838cb6b5f1e548307ea79d119c890c54e954453cf1a264e1d14ed"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Usage: spork -c IP:PORT" fullword ascii wide
		$s2 = "connect-back IP address and port number"

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and 1 of them
}