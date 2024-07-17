
rule NCSC_Sparrowdoor_Config : FILE
{
	meta:
		description = "Targets the XOR encoded loader config and shellcode in the file libhost.dll using the known position of the XOR key."
		author = "NCSC"
		id = "16eec5b6-c77a-585d-88f3-2c86abdbf2bd"
		date = "2022-02-28"
		modified = "2022-07-06"
		reference = "https://www.ncsc.gov.uk/files/NCSC-MAR-SparrowDoor.pdf"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/NCSC/SparrowDoor_config.yar#L1-L14"
		license_url = "N/A"
		logic_hash = "bd52496b6e7cabc875a277ce7d49f6b891c3f61591edef295dbee43716c15509"
		score = 75
		quality = 80
		tags = "FILE"
		hash1 = "c1890a6447c991880467b86a013dbeaa66cc615f"

	condition:
		( uint16(0)!=0x5A4D) and ( uint16(0)!=0x8b55) and ( uint32(0)^ uint32(0x4c)==0x00) and ( uint32(0)^ uint32(0x34)==0x00) and ( uint16(0)^ uint16(0x50)==0x8b55)
}