rule SECUINFRA_MAL_Redline_Certificate_Geforce : FILE
{
	meta:
		description = "Detects Certificate used by Redline Stealer"
		author = "SECUINFRA Falcon Team"
		id = "70081810-704e-5734-8a78-f97e17989460"
		date = "2022-02-13"
		modified = "2022-02-13"
		reference = "https://bazaar.abuse.ch/sample/f36c1c2f6b6f334be93b72fccb8e46cadd59304dc244b3a5aabecc8f4018eb77"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Stealer/redline_stealer.yar#L18-L31"
		license_url = "N/A"
		logic_hash = "04e9bfd886be1550b0efd22f0098cc13a5fb6e7cae30b866a4066d0c8f433367"
		score = 75
		quality = 70
		tags = "FILE"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].issuer contains "Palit GeForce RTX 3070 Dual H21 LHR" and pe.signatures[i].serial=="11:cd:b5:d5:9d:fb:90:84:45:f3:a7:22:25:47:a4:54")
}