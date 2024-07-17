
rule CAPE_Lokibot : FILE
{
	meta:
		description = "LokiBot Payload"
		author = "kevoreilly"
		id = "8cdf69e2-ecac-5241-adba-c458cce0610f"
		date = "2022-02-01"
		modified = "2022-02-01"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/LokiBot.yar#L1-L12"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "a5b3d518371138740e913d2d6ce4fa22d3da5cea7e034c7d6b4b502e6bf44b06"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "LokiBot Payload"

	strings:
		$a1 = "DlRycq1tP2vSeaogj5bEUFzQiHT9dmKCn6uf7xsOY0hpwr43VINX8JGBAkLMZW"
		$a2 = "last_compatible_version"

	condition:
		uint16(0)==0x5A4D and ( all of ($a*))
}