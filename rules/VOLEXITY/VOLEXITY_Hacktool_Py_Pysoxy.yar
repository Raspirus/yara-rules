rule VOLEXITY_Hacktool_Py_Pysoxy : FILE MEMORY
{
	meta:
		description = "SOCKS5 proxy tool used to relay connections."
		author = "threatintel@volexity.com"
		id = "88094b55-784d-5245-9c40-b1eebf0e6e72"
		date = "2024-01-09"
		modified = "2024-01-09"
		reference = "TIB-20240109"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2024/2024-01-10 Ivanti Connect Secure/indicators/yara.yar#L85-L111"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "f73e9d3c2f64c013218469209f3b69fc868efafc151a7de979dde089bfdb24b2"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		hash1 = "e192932d834292478c9b1032543c53edfc2b252fdf7e27e4c438f4b249544eeb"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10065
		version = 3

	strings:
		$s1 = "proxy_loop" ascii
		$s2 = "connect_to_dst" ascii
		$s3 = "request_client" ascii
		$s4 = "subnegotiation_client" ascii
		$s5 = "bind_port" ascii

	condition:
		all of them
}