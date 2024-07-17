rule SIGNATURE_BASE_APT_APT41_CRACKSHOT : FILE
{
	meta:
		description = "Detects APT41 malware CRACKSHOT"
		author = "Florian Roth (Nextron Systems)"
		id = "4ec34a77-dc7f-5f27-9f0a-c98438389018"
		date = "2019-08-07"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt41.yar#L46-L64"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "70dd9edfc7f9ace7b00a35eb2ef664aa4fbaab8e2d268922d1593074897e769c"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "993d14d00b1463519fea78ca65d8529663f487cd76b67b3fd35440bcdf7a8e31"

	strings:
		$x1 = ";procmon64.exe;netmon.exe;tcpview.exe;MiniSniffer.exe;smsniff.exe" ascii
		$s1 = "RunUrlBinInMem" fullword ascii
		$s2 = "DownRunUrlFile" fullword ascii
		$s3 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36" fullword ascii
		$s4 = "%s|%s|%s|%s|%s|%s|%s|%dx%d|%04x|%08X|%s|%s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <250KB and (1 of ($x*) or 2 of them )
}