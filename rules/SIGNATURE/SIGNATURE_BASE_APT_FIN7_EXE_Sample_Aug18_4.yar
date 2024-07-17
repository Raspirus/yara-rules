import "pe"


rule SIGNATURE_BASE_APT_FIN7_EXE_Sample_Aug18_4 : FILE
{
	meta:
		description = "Detects sample from FIN7 report in August 2018"
		author = "Florian Roth (Nextron Systems)"
		id = "bead79bb-28c2-59ed-985b-e44b41e7f66a"
		date = "2018-08-01"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_fin7.yar#L142-L157"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "cd8a33c4e4f626d744e03f48e093f6a45223c74088b03185833ece8034614ca4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4b5405fc253ed3a89c770096a13d90648eac10a7fb12980e587f73483a07aa4c"

	strings:
		$s1 = "c:\\file.dat" fullword wide
		$s2 = "constructor or from DllMain." fullword ascii
		$s3 = "lineGetCallIDs" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <700KB and all of them
}