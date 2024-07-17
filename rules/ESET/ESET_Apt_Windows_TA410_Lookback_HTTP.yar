rule ESET_Apt_Windows_TA410_Lookback_HTTP : FILE
{
	meta:
		description = "Matches LookBack's hardcoded HTTP request"
		author = "ESET Research"
		id = "ca4ee437-5ac9-5715-90fb-e0e74a817bb5"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/ta410/ta410.yar#L333-L349"
		license_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/LICENSE"
		logic_hash = "0e777f56136cd11d62abdf4f120410d5fe9cd522cfc06afbf085414a96279bf7"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "POST http://%s/status.php?r=%d%d HTTP/1.1\x0d\nAccept: text/html, application/xhtml+xml, */*\x0d\nAccept-Language: en-us\x0d\nUser-Agent: %s\x0d\nContent-Type: application/x-www-form-urlencoded\x0d\nAccept-Encoding: gzip, deflate\x0d\nHost: %s\x0d\nContent-Length: %d\x0d\nConnection: Keep-Alive\x0d\nCache-Control: no-cache\x0d\n\x0d\n" ascii wide
		$s2 = "id=1&op=report&status="

	condition:
		uint16(0)==0x5a4d and all of them
}