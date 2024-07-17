
rule ELASTIC_Windows_Vulndriver_Asrock_0Eca57Dc : FILE
{
	meta:
		description = "Name: AsrSetupDrv103.sys, Version: 1.00.00.0000 built by: WinDDK"
		author = "Elastic Security"
		id = "0eca57dc-3800-4b0f-99dd-151fcac82136"
		date = "2023-07-20"
		modified = "2023-07-20"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_Asrock.yar#L41-L62"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9d9346e6f46f831e263385a9bd32428e01919cca26a035bbb8e9cb00bf410bc3"
		hash = "a0728184caead84f2e88777d833765f2d8af6a20aad77b426e07e76ef91f5c3f"
		logic_hash = "82a0cba571dc58ed8d3fd87d3650ec0c1016e6c8e972547f6120ba91c8febce1"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "6c73b37f5e749161b4fb2f076e82ceb02345894b5db8e1a187019b54e3d1a154"
		threat_name = "Windows.Vulndriver.Asrock"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 [1-8] 41 00 73 00 72 00 53 00 65 00 74 00 75 00 70 00 44 00 72 00 76 00 31 00 30 00 33 00 2E 00 73 00 79 00 73 }
		$file_version = { 46 00 69 00 6C 00 65 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E [1-8] 31 00 2E 00 30 00 30 00 2E 00 30 00 30 00 2E 00 30 00 30 00 30 00 30 00 20 00 62 00 75 00 69 00 6C 00 74 00 20 00 62 00 79 00 3A 00 20 00 57 00 69 00 6E 00 44 00 44 00 4B }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name and $file_version
}