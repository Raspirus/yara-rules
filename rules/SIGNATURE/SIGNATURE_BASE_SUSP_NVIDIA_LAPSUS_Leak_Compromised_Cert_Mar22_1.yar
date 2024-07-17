rule SIGNATURE_BASE_SUSP_NVIDIA_LAPSUS_Leak_Compromised_Cert_Mar22_1 : FILE
{
	meta:
		description = "Detects a binary signed with the leaked NVIDIA certifcate and compiled after March 1st 2022"
		author = "Florian Roth (Nextron Systems)"
		id = "8bc7460f-a1c4-5157-8c2d-34d3a6c9c7e9"
		date = "2022-03-03"
		modified = "2022-03-04"
		reference = "https://twitter.com/cyb3rops/status/1499514240008437762"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_nvidia_leaked_cert.yar#L4-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "e7e9e58ec1e3922471ad3ffd4ad9fbb3ac4b3c3841c35d1cd8886607f3cf1ab9"
		score = 70
		quality = 85
		tags = "FILE"

	condition:
		uint16(0)==0x5a4d and filesize <100MB and pe.timestamp>1646092800 and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].issuer contains "VeriSign Class 3 Code Signing 2010 CA" and (pe.signatures[i].serial=="43:bb:43:7d:60:98:66:28:6d:d8:39:e1:d0:03:09:f5" or pe.signatures[i].serial=="14:78:1b:c8:62:e8:dc:50:3a:55:93:46:f5:dc:c5:18"))
}