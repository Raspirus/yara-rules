import "pe"


rule SIGNATURE_BASE_TA17_318B_Volgmer : FILE
{
	meta:
		description = "Malformed User Agent in Volgmer malware"
		author = "US CERT"
		id = "20a7f64b-0fee-5235-ac91-2fc811497ac6"
		date = "2017-11-15"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-318B"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ta17_318B.yar#L9-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2b3a7e501214767b7d79b33fb560b5611fa3726036a0c98d6f1904a55f306e40"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s = "Mozillar/"

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and $s
}