rule TELEKOM_SECURITY_Get_Windows_Proxy_Configuration : CAPABILITY HACKTOOL
{
	meta:
		description = "Queries Windows Registry for proxy configuration"
		author = "Thomas Barabosch, Deutsche Telekom Security"
		id = "b67b0b70-a95f-5c65-a522-ef4f41e36159"
		date = "2022-01-14"
		modified = "2023-12-12"
		reference = "https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-ie-clientnetworkprotocolimplementation-hklmproxyserver"
		source_url = "https://github.com/telekom-security/malware_analysis//blob/bf832d97e8fd292ec5e095e35bde992a6462e71c/hacktools/hacktools.yar#L44-L57"
		license_url = "N/A"
		logic_hash = "db52782a56d42f6e460466ea46993490bbbceeb7422d45211f064edb2e37a8eb"
		score = 75
		quality = 70
		tags = "CAPABILITY, HACKTOOL"

	strings:
		$a = "Software\\Microsoft\\Windows\\Currentversion\\Internet Settings" ascii wide
		$b = "ProxyEnable" ascii wide
		$c = "ProxyServer" ascii wide

	condition:
		all of them
}