rule DR4K0NIA_MAL_Msil_Net_Niximports_Loader : FILE
{
	meta:
		description = "Detects NixImports .NET loader"
		author = "dr4k0nia"
		id = "ba0d072d-674a-5790-9381-4dac98204268"
		date = "2023-05-21"
		modified = "2023-05-22"
		reference = "https://github.com/dr4k0nia/NixImports"
		source_url = "https://github.com/dr4k0nia/yara-rules/blob/4b10f9b79a4cfb3ec9cb5675f32cc7ee6885fbd8/dotnet/msil_mal_niximports_loader.yar#L1-L21"
		license_url = "https://github.com/dr4k0nia/yara-rules/blob/4b10f9b79a4cfb3ec9cb5675f32cc7ee6885fbd8/LICENSE.md"
		logic_hash = "79421b2677705852f893fa53478deb2e4aa8bd354ac05cbf5438a3a2a15d70bf"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$op_pe = {C2 95 C2 97 C2 B2 C2 92 C2 82 C2 82 C2 8E C2 82 C2 82 C2 82 C2 82 C2 86 C2 82}
		$op_delegate = {20 F0 C7 FF 80 20 83 BF 7F 1F 14 14}
		$a1 = "GetRuntimeProperties" ascii fullword
		$a2 = "GetTypes" ascii fullword
		$a3 = "GetRuntimeMethods" ascii fullword
		$a4 = "netstandard" ascii fullword

	condition:
		uint16(0)==0x5a4d and filesize <3MB and all of ($a*) and 2 of ($op*)
}