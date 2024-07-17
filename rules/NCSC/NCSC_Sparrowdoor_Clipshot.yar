import "pe"


rule NCSC_Sparrowdoor_Clipshot : FILE
{
	meta:
		description = "The SparrowDoor loader contains a feature it calls clipshot, which logs clipboard data to a file."
		author = "NCSC"
		id = "186e694b-6ae1-5042-847a-f54708dc76ef"
		date = "2022-02-28"
		modified = "2022-07-06"
		reference = "https://www.ncsc.gov.uk/files/NCSC-MAR-SparrowDoor.pdf"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/NCSC/SparrowDoor_clipshot.yar#L3-L20"
		license_url = "N/A"
		logic_hash = "7662e3be2752ac82d6cfe4b2e420157e78367c201c25ae34b5d956dc53ba20ae"
		score = 75
		quality = 80
		tags = "FILE"
		hash1 = "989b3798841d06e286eb083132242749c80fdd4d"

	strings:
		$exsting_cmp = {8B 1E 3B 19 75 ?? 83 E8 04 83 C1 04 83 C6 04 83 F8 04}
		$time_format_string = "%d/%d/%d %d:%d" ascii
		$cre_fil_args = {6A 00 68 80 00 00 00 6A 04 6A 00 6A 02 68 00 00 00 40 52}

	condition:
		( uint16(0)==0x5A4D) and uint32( uint32(0x3C))==0x00004550 and all of them and (pe.imports("User32.dll","OpenClipboard") and pe.imports("User32.dll","GetClipboardData") and pe.imports("Kernel32.dll","GetLocalTime") and pe.imports("Kernel32.dll","GlobalSize"))
}