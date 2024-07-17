
rule SIGNATURE_BASE_Xrat_1 : FILE
{
	meta:
		description = "Detects Patchwork malware"
		author = "Florian Roth (Nextron Systems)"
		id = "170c926a-2020-5269-85b8-6fe9ad28ef76"
		date = "2017-12-11"
		modified = "2023-12-05"
		reference = "https://goo.gl/Pg3P4W"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_xrat.yar#L12-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "032c5af4f34959783102977543d2caf6199b8d1880a64797882f591e36c64d69"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "92be93ec4cbe76182404af0b180871fbbfa3c7b34e4df6745dbcde480b8b4b3b"
		hash2 = "f1a45adcf907e660ec848c6086e28c9863b7b70d0d38417dd05a4261973c955a"

	strings:
		$x1 = "\" -CHECK & PING -n 2 127.0.0.1 & EXIT" fullword wide
		$x2 = "xClient.Core.Elevation" fullword ascii
		$x3 = ">> Welcome to MAX-Shell :Session created" fullword wide
		$x4 = "xClient.Properties.Resources.resources" fullword ascii
		$x5 = "<description>My UAC Compatible application</description>" fullword ascii
		$s1 = "ping -n 20 localhost > nul" fullword wide
		$s2 = "DownloadAndExecute" fullword ascii
		$s3 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.114 Safari/537.36" fullword wide
		$s4 = "Client.exe" fullword ascii
		$s5 = "Microsoft -Defender" fullword wide
		$s6 = "Microsoft- Defender" fullword wide
		$s7 = "set_RunHidden" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and (1 of ($x*) or 3 of them )
}