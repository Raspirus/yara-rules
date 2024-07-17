import "pe"


rule SBOUSSEADEN_Maliciousdllgenerator : FILE
{
	meta:
		description = "MaliciousDLLGenerator default decoder and export name"
		author = "SBousseaden"
		id = "a5f4d0b2-ef40-5e69-935e-208464944487"
		date = "2020-06-07"
		modified = "2020-06-08"
		reference = "https://github.com/Mr-Un1k0d3r/MaliciousDLLGenerator"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/MaliciousDLLGenerator.yara#L3-L12"
		license_url = "N/A"
		logic_hash = "70976f4a7043f52277a1d436c1725b2583383880d7158c74c4d93f3e603708c7"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$decoder = {E8 00 00 00 00 5B 48 31 C0 48 89 C1 B1 80 48 83 C3 11 48 F7 14 CB E2 FA 48 83 C3 08 53 C3}

	condition:
		uint16(0)==0x5a4d and $decoder and pe.exports("Init") and pe.number_of_exports==2
}