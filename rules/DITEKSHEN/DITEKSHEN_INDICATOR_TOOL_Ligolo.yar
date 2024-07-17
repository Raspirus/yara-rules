import "pe"


rule DITEKSHEN_INDICATOR_TOOL_Ligolo : FILE
{
	meta:
		description = "Detects Ligolo tool for establishing SOCKS5 or TCP tunnels from a reverse connection"
		author = "ditekSHen"
		id = "cc461fd1-9a2f-59ce-af74-a0f55b8850b1"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1371-L1385"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "b515dc184013c2f67d37e42d7172e2471b3a93c94024be12c7f587296287282d"
		score = 75
		quality = 73
		tags = "FILE"

	strings:
		$p1 = "/ligolo/main.go" ascii
		$p2 = "/armon/go-socks5" ascii
		$s1 = "main.StartLigolo" fullword ascii
		$s2 = "main.handleRelay" fullword ascii
		$s3 = "main.startSocksProxy" fullword ascii
		$s4 = "_main.tlsFingerprint" fullword ascii
		$s5 = "main.verifyTlsCertificate" fullword ascii

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0x457f or uint16(0)==0xfacf) and (( all of ($p*) and 1 of ($s*)) or all of ($s*) or (1 of ($p*) and 4 of ($s*)))
}