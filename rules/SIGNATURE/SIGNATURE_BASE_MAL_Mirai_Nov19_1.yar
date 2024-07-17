
rule SIGNATURE_BASE_MAL_Mirai_Nov19_1 : FILE
{
	meta:
		description = "Detects Mirai malware"
		author = "Florian Roth (Nextron Systems)"
		id = "40edcb29-9e10-5b87-ba79-8e3f629829e5"
		date = "2019-11-13"
		modified = "2023-12-05"
		reference = "https://twitter.com/bad_packets/status/1194049104533282816"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_mirai.yar#L140-L157"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e1202a9cd445c590c359a9c93e635292f8cf7f09291f4d8504ad9ce6679f6a47"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "bbb83da15d4dabd395996ed120435e276a6ddfbadafb9a7f096597c869c6c739"
		hash2 = "fadbbe439f80cc33da0222f01973f27cce9f5ab0709f1bfbf1a954ceac5a579b"

	strings:
		$s1 = "SERVZUXO" fullword ascii
		$s2 = "-loldongs" fullword ascii
		$s3 = "/dev/null" fullword ascii
		$s4 = "/bin/busybox" fullword ascii
		$sc1 = { 47 72 6F 75 70 73 3A 09 30 }

	condition:
		uint16(0)==0x457f and filesize <=100KB and 4 of them
}