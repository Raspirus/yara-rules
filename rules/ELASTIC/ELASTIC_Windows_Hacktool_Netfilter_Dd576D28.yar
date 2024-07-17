rule ELASTIC_Windows_Hacktool_Netfilter_Dd576D28 : FILE
{
	meta:
		description = "Detects Windows Hacktool Netfilter (Windows.Hacktool.NetFilter)"
		author = "Elastic Security"
		id = "dd576d28-b3e7-46b7-b19f-af37af434082"
		date = "2022-04-04"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_NetFilter.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "88cfe6d7c81d0064045c4198d6ec7d3c50dc3ec8e36e053456ed1b50fc8c23bf"
		logic_hash = "7635ed94ca77c7705df4d2a9c5546ece86bf831b5bf5355943419174e0387b86"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "b47477c371819a456ab24e158d6649e89b4d1756dc6da0b783b351d40b034fac"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\NetProxyDriver.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}