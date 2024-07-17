rule SIGNATURE_BASE_MAL_ELF_SALTWATER_Jun23_1 : CVE_2023_2868 FILE
{
	meta:
		description = "Detects SALTWATER malware used in Barracuda ESG exploitations (CVE-2023-2868)"
		author = "Florian Roth"
		id = "10a038f6-6096-5d3a-aaf5-db441685102b"
		date = "2023-06-07"
		modified = "2023-12-05"
		reference = "https://www.barracuda.com/company/legal/esg-vulnerability"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_lnx_barracuda_cve_2023_2868.yar#L21-L46"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "cb35898c0ee726170da93b4364920ac065f083f9f02db8eb5d293b1ce127cb78"
		score = 80
		quality = 85
		tags = "CVE-2023-2868, FILE"
		hash1 = "601f44cc102ae5a113c0b5fe5d18350db8a24d780c0ff289880cc45de28e2b80"

	strings:
		$x1 = "libbindshell.so"
		$s1 = "ShellChannel"
		$s2 = "MyWriteAll"
		$s3 = "CheckRemoteIp"
		$s4 = "run_cmd"
		$s5 = "DownloadByProxyChannel"
		$s6 = "[-] error: popen failed"
		$s7 = "/home/product/code/config/ssl_engine_cert.pem"

	condition:
		uint16(0)==0x457f and filesize <6000KB and ((1 of ($x*) and 2 of them ) or 3 of them ) or all of them
}