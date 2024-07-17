rule ARKBIRD_SOLG_APT_MAL_Donot_Loader_June_2020_1 : FILE
{
	meta:
		description = "Detect loader malware used by APT Donot for drops the final stage"
		author = "Arkbird_SOLG"
		id = "ec4cac12-529f-56d2-bbc0-5fe30424b10b"
		date = "2020-06-22"
		modified = "2020-06-22"
		reference = "https://twitter.com/ccxsaber/status/1274978583463649281"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-06-22/APT_MAL_Donot_Loader_June_2020_1.yar#L3-L22"
		license_url = "N/A"
		logic_hash = "986deffd48c1fb707948b00e1e200fa6538d4c73a32ab89f5119403f9bf0d734"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "1ff33d1c630db0a0b8b27423f32d15cc9ef867349ac71840aed47c90c526bb6b"

	strings:
		$s1 = "C:\\Users\\spartan\\Documents\\Visual Studio 2010\\new projects\\frontend\\Release\\test.pdb" fullword ascii
		$s2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36 Edg/81.0.416.68" fullword ascii
		$s3 = "bbLorkybbYngxkjbb]khbbmgvjgz4k~k" fullword ascii
		$s4 = "8&8-8X8.959?9Q9h9v9|9" fullword ascii
		$s5 = "0$0h4h5l5p5t5x5|5" fullword ascii
		$s6 = "?&?+?1?7?M?T?g?z?" fullword ascii
		$s7 = "12.02.1245" fullword ascii
		$s8 = ">>?C?L?[?~?" fullword ascii
		$s9 = "6*6=6P6b6" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <30KB and 7 of them
}