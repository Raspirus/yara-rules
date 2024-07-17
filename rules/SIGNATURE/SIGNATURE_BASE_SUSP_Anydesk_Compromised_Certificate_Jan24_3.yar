rule SIGNATURE_BASE_SUSP_Anydesk_Compromised_Certificate_Jan24_3 : FILE
{
	meta:
		description = "Detects binaries signed with a compromised signing certificate of AnyDesk after it was revoked (philandro Software GmbH, 0DBF152DEAF0B981A8A938D53F769DB8; version that uses dates for validation)"
		author = "Florian Roth"
		id = "9610e61c-25d7-53e8-ba3f-b78b3d108aa3"
		date = "2024-02-02"
		modified = "2024-04-24"
		reference = "https://anydesk.com/en/public-statement"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_anydesk_compromised_cert_feb23.yar#L58-L77"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "fdd1068abfba52c9a40fd2b6628a5c67775eb31815e6d53bfc4655080d9b240e"
		score = 75
		quality = 85
		tags = "FILE"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and pe.signatures[i].serial=="0d:bf:15:2d:ea:f0:b9:81:a8:a9:38:d5:3f:76:9d:b8" and (pe.signatures[i].not_before>1706486400 or pe.timestamp>1706486400))
}