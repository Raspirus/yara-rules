import "pe"


rule DITEKSHEN_INDICATOR_TOOL_PROX_Lanproxy : FILE
{
	meta:
		description = "Detects lanproxy-go-client"
		author = "ditekSHen"
		id = "71fc23d9-9aae-5666-832b-90cf5a86c474"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L660-L675"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "13a5aaea0fb522e3badb4a60d2db8d7dd46e5721bd6dc2e2b2e29d49e197c375"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "serverShare" fullword ascii
		$s2 = "parkingOnChan" fullword ascii
		$s3 = "{{join .Names \", \"}}{{\"\\t\"}}{{.Usage}}{{end}}{{end}}{{end}}{{end}}{{" ascii
		$s4 = "</table></thead></tbody>" fullword ascii
		$s5 = "value=aacute;abreve;addressagrave;alt -> andand;angmsd;angsph;any -> apacir;approx;articleatilde;barvee;barwed;bdoUxXvbecaus;ber" ascii
		$s6 = "/dev/urandom127.0.0.1:" ascii
		$s7 = "non-IPv4 addressnon-IPv6 addressntrianglelefteq;object is remotepacer: H_m_prev=reflect mismatchregexp: Compile(remote I/O error" ascii
		$s8 = ".WithDeadline(.in-addr.arpa." ascii

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0x457f) and 6 of them
}