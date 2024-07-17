
rule NCSC_Sparrowdoor_Loader : FILE
{
	meta:
		description = "Targets code features of the SparrowDoor loader. This rule detects the previous variant and this new variant."
		author = "NCSC"
		id = "7107cb82-c4c9-503f-b006-baec6b667498"
		date = "2022-02-28"
		modified = "2022-07-06"
		reference = "https://www.ncsc.gov.uk/files/NCSC-MAR-SparrowDoor.pdf"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/NCSC/SparrowDoor_loader.yar#L1-L15"
		license_url = "N/A"
		logic_hash = "fa1bd386114d912722a5101a0112355dec654e2e9446c885c12946c7fae1c8f4"
		score = 75
		quality = 80
		tags = "FILE"
		hash1 = "989b3798841d06e286eb083132242749c80fdd4d"

	strings:
		$xor_algo = {8B D0 83 E2 03 8A 54 14 10 30 14 30 40 3B C1}
		$rva = {8D B0 [4] 8D 44 24 ?? 50 6A 40 6A 05 56}
		$lj = {2B CE 83 E9 05 8D [3] 52 C6 06 E9 89 4E 01 8B [3] 50 6A 05 56}

	condition:
		( uint16(0)==0x5A4D) and uint32( uint32(0x3C))==0x00004550 and all of them
}