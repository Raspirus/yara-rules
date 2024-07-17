rule SIGNATURE_BASE_APT_FIN7_EXE_Sample_Aug18_10 : FILE
{
	meta:
		description = "Detects sample from FIN7 report in August 2018"
		author = "Florian Roth (Nextron Systems)"
		id = "2c6f557e-31d3-5377-a3fa-4f1507f28386"
		date = "2018-08-01"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_fin7.yar#L231-L248"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1d6dba0c858eacea5bd67682a588105a2ff09d10bb60d9888ace07609c9b33de"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8cc02b721683f8b880c8d086ed055006dcf6155a6cd19435f74dd9296b74f5fc"

	strings:
		$c1 = { 00 4C 00 65 00 67 00 61 00 6C 00 43 00 6F 00 70
               00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 43
               00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74
               00 20 00 31 00 20 00 2D 00 20 00 31 00 39 00 }

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 1 of them
}