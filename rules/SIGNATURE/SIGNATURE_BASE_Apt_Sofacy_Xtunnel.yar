rule SIGNATURE_BASE_Apt_Sofacy_Xtunnel : FILE
{
	meta:
		description = "Sofacy Malware - German Bundestag"
		author = "Claudio Guarnieri"
		id = "aef091b5-cedf-5443-ab61-8b2dbc7e77fd"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_sofacy_xtunnel_bundestag.yar#L3-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2478d9d8996bf4a142e39eac0e2d6af718d364be080a89530812615595777efd"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$xaps = ":\\PROJECT\\XAPS_"
		$variant11 = "XAPS_OBJECTIVE.dll"
		$variant12 = "start"
		$variant21 = "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0"
		$variant22 = "is you live?"
		$mix1 = "176.31.112.10"
		$mix2 = "error in select, errno %d"
		$mix3 = "no msg"
		$mix4 = "is you live?"
		$mix5 = "127.0.0.1"
		$mix6 = "err %d"
		$mix7 = "i`m wait"
		$mix8 = "hello"
		$mix9 = "OpenSSL 1.0.1e 11 Feb 2013"
		$mix10 = "Xtunnel.exe"

	condition:
		(( uint16(0)==0x5A4D) or ( uint16(0)==0xCFD0)) and (($xaps) or ( all of ($variant1*)) or ( all of ($variant2*)) or (6 of ($mix*)))
}