
rule ELCEEF_ZIP_High_Ratio_Single_Doc : FILE
{
	meta:
		description = "Detects ZIP archives containing single MS Word document with unusually high compression ratio"
		author = "marcin@ulikowski.pl"
		id = "0fbe89d9-1bf5-50a9-b6c1-1d739162a2ba"
		date = "2023-03-08"
		modified = "2023-03-08"
		reference = "https://github.com/elceef/yara-rulz"
		source_url = "https://github.com/elceef/yara-rulz/blob/05834717d1464d5efce8ad9d688ff7b53886a0bb/rules/ZIP_High_Ratio_Single_Doc.yara#L8-L27"
		license_url = "https://github.com/elceef/yara-rulz/blob/05834717d1464d5efce8ad9d688ff7b53886a0bb/LICENSE"
		logic_hash = "470300b8d6356cff43a1e2be3a23a97be5d1e2ce5a76f2fb2eccdbbb47a4d327"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "4d9a6dfca804989d40eeca9bb2d90ef33f3980eb07ca89bbba06d0ef4b37634b"
		hash2 = "4bc2d14585c197ad3aa5836b3f7d9d784d7afe79856e0ddf850fc3c676b6ecb1"

	strings:
		$magic = { 50 4b 03 04 }
		$ext = ".doc"

	condition:
		filesize <1MB and $magic at 0 and #magic==1 and uint32(22)>1024*1024*100 and $ext at ( uint16(26)+26)
}