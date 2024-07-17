rule DR4K0NIA_Msil_Susp_Obf_Antidump : FILE
{
	meta:
		description = "No description has been set in the source file - Dr4k0nia"
		author = "dr4k0nia"
		id = "d9217ade-a016-548e-b63f-f6ee78ff8775"
		date = "2023-12-03"
		modified = "2023-03-13"
		reference = "https://github.com/dr4k0nia/yara-rules"
		source_url = "https://github.com/dr4k0nia/yara-rules/blob/4b10f9b79a4cfb3ec9cb5675f32cc7ee6885fbd8/dotnet/msil_susp_obf_antidump.yar#L7-L39"
		license_url = "https://github.com/dr4k0nia/yara-rules/blob/4b10f9b79a4cfb3ec9cb5675f32cc7ee6885fbd8/LICENSE.md"
		hash = "ef7bb2464a2b430aa98bd65a1a40b851b57cb909ac0aea3e53729c0ff900fa42"
		logic_hash = "18cfc720f54b2178398f8214591a3fb777ea11e67a8a6d2ce26cc4891a62fd35"
		score = 65
		quality = 85
		tags = "FILE"
		version = "1.0"

	strings:
		$import0 = "ZeroMemory"
		$import1 = "VirtualProtect"
		$importt2 = "GetCurrentProcess"
		$array0 = {08 00 00 00 0c 00 00 00 10 00 00 00 14 00 00 00
		18 00 00 00 1c 00 00 00 24 00 00 00}
		$array1 = {04 00 00 00 16 00 00 00 18 00 00 00 40 00 00 00
		42 00 00 00 44 00 00 00 46 00 00 00 48 00 00 00
		4a 00 00 00 4c 00 00 00 5c 00 00 00 5e 00 00 00}
		$array2 = {00 00 00 00 08 00 00 00 0c 00 00 00 10 00 00 00
		16 00 00 00 1c 00 00 00 20 00 00 00 28 00 00 00
		2c 00 00 00 34 00 00 00 3c 00 00 00 4c 00 00 00
		50 00 00 00 54 00 00 00 58 00 00 00 60 00 00 00
		64 00 00 00 68 00 00 00 6c 00 00 00 70 00 00 00
		74 00 00 00 04 01 00 00 08 01 00 00 0c 01 00 00
		10 01 00 00 14 01 00 00 1c 01 00 00}

	condition:
		uint16(0)==0x5a4d and dotnet.is_dotnet and all of them
}