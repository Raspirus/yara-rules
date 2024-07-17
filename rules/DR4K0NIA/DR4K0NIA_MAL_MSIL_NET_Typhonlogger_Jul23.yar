rule DR4K0NIA_MAL_MSIL_NET_Typhonlogger_Jul23 : FILE
{
	meta:
		description = "Detects TyphonLogger .NET payloads"
		author = "dr4k0nia"
		id = "2fbc1d9e-9c07-560b-9476-a176cdbe1bad"
		date = "2023-11-07"
		modified = "2023-07-11"
		reference = "https://github.com/dr4k0nia/yara-rules"
		source_url = "https://github.com/dr4k0nia/yara-rules/blob/4b10f9b79a4cfb3ec9cb5675f32cc7ee6885fbd8/dotnet/mal_msil_typhon_logger.yar#L1-L21"
		license_url = "https://github.com/dr4k0nia/yara-rules/blob/4b10f9b79a4cfb3ec9cb5675f32cc7ee6885fbd8/LICENSE.md"
		hash = "fc8733c217b49ca14702a59a637efc7dba6a2993d57e67424513ce2f5e9d8ed8"
		logic_hash = "5c22aab1942e31095989b8267e0231191718d4ec44eb3afc6a50f929aae872c8"
		score = 75
		quality = 81
		tags = "FILE"

	strings:
		$sa1 = "SetWindowsHookEx" ascii fullword
		$sa2 = "iphlpapi.dll" ascii fullword
		$sa3 = "SendARP" ascii fullword
		$sa4 = "costura.bouncycastle.crypto.dll.compressed" ascii fullword
		$op1 = {51 32 46 79 64 47 55 67 51 6D 78 68 62 6D 4E 6F 5A 53 42 44 59 58 4A 6B}
		$op2 = {53 57 35 7A 64 47 45 67 55 47 46 35 62 57 56 75 64 43 42 44 59 58 4A 6B}
		$op3 = {20 25 32 C4 C1 35 4C 11 06 20 6B 6D AC 1D 35 1D 11 06 20 4B A6 CA 11 3B 59 01 00 00 11 06 20 6B 6D AC 1D}
		$sx = "New Projects\\EmeraldLogger\\EmeraldLogger\\obj\\" ascii

	condition:
		uint16(0)==0x5a4d and ($sx or ( all of ($sa*) and 2 of ($op*)))
}