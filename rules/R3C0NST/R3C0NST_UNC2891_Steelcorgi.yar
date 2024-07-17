rule R3C0NST_UNC2891_Steelcorgi : FILE
{
	meta:
		description = "Detects UNC2891 Steelcorgi packed ELF binaries"
		author = "Frank Boldewin (@r3c0nst)"
		id = "94da7da5-5fc3-5221-97d6-1854aa7b1959"
		date = "2022-03-30"
		modified = "2023-01-05"
		reference = "https://github.com/fboldewin/YARA-rules/"
		source_url = "https://github.com/fboldewin/YARA-rules//blob/54e9e6899b258b72074b2b4db6909257683240c2/UNC2891_Steelcorgi.yar#L1-L17"
		license_url = "N/A"
		logic_hash = "4f956b9eaec66bc606ffd0afa2fe9303194e9a8c12d4c3de6ab2334c9856dd99"
		score = 75
		quality = 90
		tags = "FILE"
		hash1 = "0760cd30d18517e87bf9fd8555513423db1cd80730b47f57167219ddbf91f170"
		hash2 = "3560ed07aac67f73ef910d0b928db3c0bb5f106b5daee054666638b6575a89c5"
		hash3 = "5b4bb50055b31dbd897172583c7046dd27cd03e1e3d84f7a23837e8df7943547"

	strings:
		$pattern1 = {70 61 64 00 6C 63 6B 00}
		$pattern2 = {FF 72 FF 6F FF 63 FF 2F FF 73 FF 65 FF 6C FF 66 FF 2F FF 65 FF 78 FF 65}

	condition:
		uint32(0)==0x464c457f and all of them
}