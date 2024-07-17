rule SECUINFRA_MAL_Redline_Certificate_Bosch : FILE
{
	meta:
		description = "Detects Certificate used by Redline Stealer"
		author = "SECUINFRA Falcon Team"
		id = "a91d0510-ab4e-5f22-bcce-9a42beff5190"
		date = "2022-12-02"
		modified = "2022-02-13"
		reference = "https://bazaar.abuse.ch/sample/60e40ccfc16ca9f36dee7ec2b4e2fc81398ff408bf7cc63fb7ddf0fef1d4b72b"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Stealer/redline_stealer.yar#L3-L16"
		license_url = "N/A"
		logic_hash = "b3084bee5151543c0931bef9d320805d9e4d63c25be029da4e592d5a0b080a0e"
		score = 75
		quality = 70
		tags = "FILE"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].issuer contains "BOSCH BOSCH SDS-plus Professional 607557501" and pe.signatures[i].serial=="72:76:34:57:ef:50:d5:b0:4e:00:b3:74:ab:c6:ff:11")
}