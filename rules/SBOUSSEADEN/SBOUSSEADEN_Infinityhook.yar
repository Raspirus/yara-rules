rule SBOUSSEADEN_Infinityhook : FILE
{
	meta:
		description = "Infinityhook is a legit research PoC to hook NT Syscalls bypassing PatchGuard"
		author = "SBousseaden"
		id = "82f4eef2-fca7-58b1-a85c-3c237f523740"
		date = "2020-09-07"
		modified = "2020-07-10"
		reference = "https://github.com/everdox/InfinityHook"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/infinityhook.yara#L1-L17"
		license_url = "N/A"
		logic_hash = "c621ce3be8049de7584af73ca4472df5561d3c4ac8b458937db2ad68fdcbe2d8"
		score = 75
		quality = 73
		tags = "FILE"

	strings:
		$EtwpDebuggerPattern = {00 2C 08 04 38 0C 00}
		$SMV = {00 00 76 66 81 3A 02 18 50 00 75 0E 48 83 EA 08 B8 33 0F 00}
		$KVASCODE = {4B 56 41 53 43 4F 44 45}
		$CKL = "Circular Kernel Context Logger" wide nocase

	condition:
		uint16(0)==0x5a4d and all of them
}