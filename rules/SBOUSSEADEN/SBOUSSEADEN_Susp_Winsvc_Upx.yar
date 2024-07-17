rule SBOUSSEADEN_Susp_Winsvc_Upx : FILE
{
	meta:
		description = "broad hunt for any PE exporting ServiceMain API and upx packed"
		author = "SBousseaden"
		id = "883691fe-3858-5177-97ca-122ff2ec54af"
		date = "2019-01-28"
		modified = "2020-06-05"
		reference = "https://github.com/sbousseaden/YaraHunts/"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/susp_winsvc_upx.yara#L3-L13"
		license_url = "N/A"
		logic_hash = "85b1932eaab4e559f0805aa76ad9b58553708391b3ac894a8e4f1cf34470dcb7"
		score = 65
		quality = 75
		tags = "FILE"

	strings:
		$upx1 = {55505830000000}
		$upx2 = {55505831000000}
		$upx_sig = "UPX!"

	condition:
		uint16(0)==0x5a4d and $upx1 in (0..1024) and $upx2 in (0..1024) and $upx_sig in (0..1024) and pe.exports("ServiceMain")
}