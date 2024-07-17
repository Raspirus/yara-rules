rule ELASTIC_Windows_Vulndriver_Fiddrv_E7875A5A : FILE
{
	meta:
		description = "Detects Intel's R/W MSR driver (fiddrv64.sys)"
		author = "Elastic Security"
		id = "e7875a5a-5a88-4bc3-9cfc-91b446dcc6aa"
		date = "2023-07-25"
		modified = "2023-07-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Vulndriver_FidDrv.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4bf4cced4209c73aa37a9e2bf9ff27d458d8d7201eefa6f6ad4849ee276ad158"
		logic_hash = "aa1635c651c8364ad2ee93b369dd583fce699001d753e46de013c476d185eef1"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "ed9ef63a9e2434a30f22f679edb99b9104eb4397968d84599c7828102312025e"
		threat_name = "Windows.VulnDriver.FidDrv"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$subject = { 06 03 55 04 03 [2] 49 6E 74 65 6C 28 52 29 20 50 72 6F 63 65 73 73 6F 72 20 49 64 65 6E 74 69 66 69 63 61 74 69 6F 6E 20 55 74 69 6C 69 74 79 }
		$read_msr = { 53 55 57 56 52 41 50 0F 32 41 58 41 89 10 5A 89 02 B8 01 00 00 00 5E 5F 5D 5B C3 }
		$write_msr = { 53 55 57 56 48 8B C2 49 8B D0 0F 30 B8 01 00 00 00 5E 5F 5D 5B C3 }
		$ioctl_check = { 48 8B 82 B8 00 00 00 8B 48 18 81 E9 84 2A 22 00 0F 84 ?? ?? ?? ?? 83 E9 04 }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and all of them
}