rule SIGNATURE_BASE_SUSP_XMRIG_Reference : FILE
{
	meta:
		description = "Detects an executable with a suspicious XMRIG crypto miner reference"
		author = "Florian Roth (Nextron Systems)"
		id = "0a7324ce-90dc-5e6a-b22a-c29eccf324e9"
		date = "2019-06-20"
		modified = "2023-12-05"
		reference = "https://twitter.com/itaitevet/status/1141677424045953024"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_suspicious_strings.yar#L330-L342"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c1e6f5fc390a8ada0688885bba7ed90372915deba5a5e7e5b0cd17ec450ce240"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "\\xmrig\\" ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 1 of them
}