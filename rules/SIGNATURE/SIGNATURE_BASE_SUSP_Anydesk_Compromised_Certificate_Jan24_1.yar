import "pe"


rule SIGNATURE_BASE_SUSP_Anydesk_Compromised_Certificate_Jan24_1 : FILE
{
	meta:
		description = "Detects binaries signed with a compromised signing certificate of AnyDesk that aren't AnyDesk itself (philandro Software GmbH, 0DBF152DEAF0B981A8A938D53F769DB8; strict version)"
		author = "Florian Roth"
		id = "8d172b04-f7f7-54df-b30c-3ee17d3cca12"
		date = "2024-02-02"
		modified = "2024-04-24"
		reference = "https://anydesk.com/en/public-statement"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_anydesk_compromised_cert_feb23.yar#L19-L36"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1b2268b1efa09ee8578f4c1ae07617ac6bebeacd3ed50598a2fc2ec4d709baa7"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$a1 = "AnyDesk Software GmbH" wide

	condition:
		uint16(0)==0x5a4d and not $a1 and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and pe.signatures[i].serial=="0d:bf:15:2d:ea:f0:b9:81:a8:a9:38:d5:3f:76:9d:b8")
}