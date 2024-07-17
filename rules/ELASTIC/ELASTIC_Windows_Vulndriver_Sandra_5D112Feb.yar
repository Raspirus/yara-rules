rule ELASTIC_Windows_Vulndriver_Sandra_5D112Feb : FILE
{
	meta:
		description = "Name: SANDRA, Version: 10.12.0.0"
		author = "Elastic Security"
		id = "5d112feb-dc0a-464c-9753-695bb510f5a8"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_Sandra.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3a364a7a3f6c0f2f925a060e84fb18b16c118125165b5ea6c94363221dc1b6de"
		logic_hash = "d234a1e74234400f51c2aa7a9fb1549be1bc422bdf585db7d2ec9ad1ec75e490"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "13572e1155a5417549508952504b891f0e4f40cb6ff911bdda6f152c051c401c"
		threat_name = "Windows.VulnDriver.Sandra"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 41 00 4E 00 44 00 52 00 41 00 00 00 }
		$version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x0c][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x09][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x0b][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name and $version
}