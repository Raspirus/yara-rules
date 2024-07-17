
rule ELASTIC_Windows_Vulndriver_Iobitunlocker_Defb90Fd : FILE
{
	meta:
		description = "Name: IObitUnlocker.sys, Version: 1.0.X.Y to 1.3.X.Y"
		author = "Elastic Security"
		id = "defb90fd-d2ac-4168-b248-f698b590a63f"
		date = "2023-07-25"
		modified = "2023-07-25"
		reference = "https://theevilbit.github.io/posts/iobit_unlocker_lpe/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_IoBitUnlocker.yar#L1-L25"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0aff83f28d70f425539fee3d6a780210d0406264f8a4eb124e32b074e8ffd556"
		hash = "5ce1a8eac73ef1d0741f34d9fb2661da322117a63bffe60ccad092da89664c42"
		logic_hash = "4b0f440c66b7c9a193f0d6675c2a4246036ebc5c0c83856f45ec40a041e9cd07"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "a2015ef9d0f3f5de47cd5c9a64953aef7a860d5cbd7e176df601c67c89294e4f"
		threat_name = "Windows.VulnDriver.IoBitUnlocker"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 [1-4] 49 00 4F 00 62 00 69 00 74 00 55 00 6E 00 6C 00 6F 00 63 00 6B 00 65 00 72 00 2E 00 73 00 79 00 73 }
		$product_version = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 [1-4] 31 00 2E 00 ( 30 | 31 | 32 | 33 ) 00 }
		$subject = { 06 03 55 04 0A [2] 49 4F 62 69 74 20 49 6E 66 6F 72 6D 61 74 69 6F 6E 20 54 65 63 68 6E 6F 6C 6F 67 79 }
		$pdb_filename = "IObitUnlocker.pdb" fullword

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and (($original_file_name and $product_version) or ($subject and $pdb_filename))
}