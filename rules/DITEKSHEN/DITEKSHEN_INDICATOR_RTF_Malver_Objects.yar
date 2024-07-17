
rule DITEKSHEN_INDICATOR_RTF_Malver_Objects : FILE
{
	meta:
		description = "Detects RTF documents with non-standard version and embeding one of the object mostly observed in exploit documents."
		author = "ditekSHen"
		id = "2d9d80e0-473e-5aac-a576-8f0002e120e2"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_office.yar#L679-L693"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "69136fb8ba180f6f86e569471bcefe8f55c61af73c66ebd6062ba7369aee9a72"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\objlink" ascii

	condition:
		uint32(0)==0x74725c7b and (( not uint8(4)==0x66 or not uint8(5)==0x31 or not uint8(6)==0x5c) and 1 of ($obj*))
}