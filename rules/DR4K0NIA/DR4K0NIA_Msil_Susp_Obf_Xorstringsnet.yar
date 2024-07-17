import "dotnet"


rule DR4K0NIA_Msil_Susp_Obf_Xorstringsnet : FILE
{
	meta:
		description = "Detects XorStringsNET string encryption, and other obfuscators derived from it"
		author = "dr4k0nia"
		id = "0bea654d-9244-5320-a815-691384decc74"
		date = "2023-03-26"
		modified = "2023-03-26"
		reference = "https://github.com/dr4k0nia/yara-rules"
		source_url = "https://github.com/dr4k0nia/yara-rules/blob/4b10f9b79a4cfb3ec9cb5675f32cc7ee6885fbd8/dotnet/msil_susp_obf_xorstringsnet.yar#L3-L16"
		license_url = "https://github.com/dr4k0nia/yara-rules/blob/4b10f9b79a4cfb3ec9cb5675f32cc7ee6885fbd8/LICENSE.md"
		logic_hash = "c494b5b64bcb63d1edd611206fb41eb9a23a940a72c3e9fc3f626e91482b1352"
		score = 65
		quality = 85
		tags = "FILE"
		version = "1.0"

	strings:
		$pattern = { 06 1E 58 07 8E 69 FE17 }

	condition:
		uint16(0)==0x5a4d and filesize <25MB and dotnet.is_dotnet and $pattern
}