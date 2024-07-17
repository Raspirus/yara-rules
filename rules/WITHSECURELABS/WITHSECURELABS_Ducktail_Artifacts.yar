rule WITHSECURELABS_Ducktail_Artifacts : FILE
{
	meta:
		description = "Detects artifacts found in files associated to DUCKTAIL malware"
		author = "WithSecure"
		id = "937c9688-b74f-5e02-838f-ab6757a8d2a1"
		date = "2022-07-18"
		modified = "2022-07-26"
		reference = "https://labs.withsecure.com/publications/ducktail"
		source_url = "https://github.com/WithSecureLabs/iocs/blob/29adc4b6c2c2850f0f385aec77ab6fc0d7a8f20c/DUCKTAIL/ducktail_artifacts.yar#L1-L20"
		license_url = "https://github.com/WithSecureLabs/iocs/blob/29adc4b6c2c2850f0f385aec77ab6fc0d7a8f20c/LICENSE"
		logic_hash = "1daa5e654058c802826b6a306b5bfc9d0c05c4ee54607e94e618a8d409ce74d9"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1.0"
		hash1 = "3dbd9e1c3d0fd6358d4adcba04fdfc0b6e8acc49"
		hash2 = "9370243589327b458486e3f7637779c2a96b4250"
		hash3 = "b98170b18b906aee771dbd4dbd31e5963a90a50e"

	strings:
		$pdb_path_1 = /[a-z]\:\\projects\\(viruttest|virot)\\/i nocase ascii
		$pdb_path_2 = /[a-z]\:\\users\\ductai\\/i nocase ascii
		$pdb_path_3 = "\\dataextractor.pdb" nocase ascii
		$email = "ductai2308@gmail.com" wide ascii

	condition:
		uint16(0)==0x5A4D and any of them
}