
rule ELASTIC_Windows_Hacktool_Netfilter_1Cae6E26 : FILE
{
	meta:
		description = "Detects Windows Hacktool Netfilter (Windows.Hacktool.NetFilter)"
		author = "Elastic Security"
		id = "1cae6e26-b0ce-4f53-b88d-975b52ebcca7"
		date = "2022-04-04"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_NetFilter.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e2ec3b2a93c473d88bfdf2deb1969d15ab61737acc1ee8e08234bc5513ee87ea"
		logic_hash = "29c0edc03934e6e7275c3870a8808e03ec85dacb1f54e10efca3123d2257db98"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "27003a6c9ad814e1ab2e7e284acfebdd18c9dd2af66eb9f44e5a9d59445fa086"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\Driver_Map.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}