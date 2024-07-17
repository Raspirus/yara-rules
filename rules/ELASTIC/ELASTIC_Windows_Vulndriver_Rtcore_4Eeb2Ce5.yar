
rule ELASTIC_Windows_Vulndriver_Rtcore_4Eeb2Ce5 : FILE
{
	meta:
		description = "Detects Windows Vulndriver Rtcore (Windows.VulnDriver.RtCore)"
		author = "Elastic Security"
		id = "4eeb2ce5-e481-4e9c-beda-2b01f259ed96"
		date = "2022-04-04"
		modified = "2022-08-30"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_RtCore.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd"
		logic_hash = "f547bce6554c60e8f3ef8e128c05533cf1f35ce0ee414d5a1c5e9a205b05d8fe"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "cebca7dc572afccf4eb600980b9cbaef0878213f91c04b4605a0cf4d0e5e541f"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\Device\\RTCore64" wide fullword
		$str2 = "Kaspersky Lab Anti-Rootkit Monitor Driver" wide fullword

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1 and not $str2
}