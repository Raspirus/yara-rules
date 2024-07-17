
rule ELCEEF_HTML_Smuggling_C : T1027 FILE
{
	meta:
		description = "Generic detection for HTML smuggling (T1027.006)"
		author = "marcin@ulikowski.pl"
		id = "ea1eafad-905b-571e-a016-8774e65bd976"
		date = "2023-04-17"
		modified = "2023-04-17"
		reference = "https://github.com/elceef/yara-rulz"
		source_url = "https://github.com/elceef/yara-rulz/blob/05834717d1464d5efce8ad9d688ff7b53886a0bb/rules/HTML_Smuggling.yara#L62-L82"
		license_url = "https://github.com/elceef/yara-rulz/blob/05834717d1464d5efce8ad9d688ff7b53886a0bb/LICENSE"
		logic_hash = "83409b0b173980975f6349e448e72fe1b2115fc7dbdec8ee7ad1826a65db17d3"
		score = 75
		quality = 75
		tags = "T1027, FILE"
		hash1 = "0b4cdfc8ae8ae17d7b6786050f1962c19858b91febb18f61f553083f57d96fea"
		hash2 = "2b99bf97f3d02ba3b44406cedd1ab31824723b56a8aae8057256cc87870c199e"
		hash3 = "904ea1ada62cfd4b964a6a3eb9bab5b98022ab000f77b75eb265a2ac44b45b37"

	strings:
		$blob = "new Blob("
		$array = "new Uint8Array("
		$mssave = { ( 2e | 22 | 27 ) 6d 73 53 61 76 65 }
		$loop = { ?? 5b 69 5d ( 3d | 20 3d | 3d 20 | 20 3d 20 ) ?? 5b 69 5d ( 2d | 20 2d | 2d 20 | 20 2d 20 ) 3? 3b }

	condition:
		filesize <5MB and $mssave and #blob==1 and #array==1 and #loop==1
}