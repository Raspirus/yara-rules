import "pe"


rule SIGNATURE_BASE_APT_APT41_POISONPLUG_3 : FILE
{
	meta:
		description = "Detects APT41 malware POISONPLUG"
		author = "Florian Roth (Nextron Systems)"
		id = "e150dd69-c611-53de-9c7d-de28d3a208dc"
		date = "2019-08-07"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt41.yar#L14-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b74b89ac382b2b839c169cd1388d86888172f133091afd079ec42c9380935fdc"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "70c03ce5c80aca2d35a5555b0532eedede24d4cc6bdb32a2c8f7e630bba5f26e"

	strings:
		$s1 = "Rundll32.exe \"%s\", DisPlay 64" fullword ascii
		$s2 = "tcpview.exe" fullword ascii
		$s3 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" fullword ascii
		$s4 = "AxEeulaVteSgeR" fullword ascii
		$s5 = "%04d-%02d-%02d_%02d-%02d-%02d.dmp" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <900KB and 3 of them
}