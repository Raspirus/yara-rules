rule ELASTIC_Windows_Vulndriver_Vbox_1B1C5Cd5 : FILE
{
	meta:
		description = "Name: VBoxDrv.sys, Version: 3.0.0.0"
		author = "Elastic Security"
		id = "1b1c5cd5-23d3-4f1f-a396-3f2b18e28b64"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_VBox.yar#L22-L42"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1684e24dae20ab83ab5462aa1ff6473110ec53f52a32cfb8c1fe95a2642c6d22"
		logic_hash = "5fcfffea021aee8d18172383df0e65f8c618fab545c800f1a7b659e8112c6c0f"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "89dd35bb023ebc03c46c0e70ac975025921da289cb3374f2912fbb323c591bd9"
		threat_name = "Windows.VulnDriver.VBox"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 56 00 42 00 6F 00 78 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
		$version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x02][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name and $version
}