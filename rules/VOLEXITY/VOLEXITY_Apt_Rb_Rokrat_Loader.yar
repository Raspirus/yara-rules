rule VOLEXITY_Apt_Rb_Rokrat_Loader : INKYSQUID
{
	meta:
		description = "Ruby loader seen loading the ROKRAT malware family."
		author = "threatintel@volexity.com"
		id = "69d09560-a769-55d3-a442-e37f10453cde"
		date = "2021-06-22"
		modified = "2021-09-02"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2021/2021-08-24 - InkySquid Part 2/indicators/yara.yar#L1-L25"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "30ae14fd55a3ab60e791064f69377f3b9de9b871adfd055f435df657f89f8007"
		score = 75
		quality = 80
		tags = "INKYSQUID"
		hash1 = "5bc52f6c1c0d0131cee30b4f192ce738ad70bcb56e84180f464a5125d1a784b2"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$magic1 = "'https://update.microsoft.com/driverupdate?id=" ascii wide
		$magic2 = "sVHZv1mCNYDO0AzI';" ascii wide
		$magic3 = "firoffset..scupd.size" ascii wide
		$magic4 = /alias UrlFilter[0-9]{2,5} eval;"/
		$s1 = "clRnbp9GU6oTZsRGZpZ"
		$s2 = "RmlkZGxlOjpQb2ludGVy"
		$s3 = "yVGdul2bQpjOlxGZklmR"
		$s4 = "XZ05WavBlO6UGbkRWaG"

	condition:
		any of ($magic*) or any of ($s*)
}