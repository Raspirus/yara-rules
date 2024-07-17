import "pe"


rule SIGNATURE_BASE_SUSP_Anydesk_Compromised_Certificate_Jan24_2 : FILE
{
	meta:
		description = "Detects binaries signed with a compromised signing certificate of AnyDesk that aren't AnyDesk itself (philandro Software GmbH, 0DBF152DEAF0B981A8A938D53F769DB8; permissive version)"
		author = "Florian Roth"
		id = "a41af8d8-ebdf-5a2f-8cf5-abd4587bdfc5"
		date = "2024-02-02"
		modified = "2024-04-24"
		reference = "https://anydesk.com/en/public-statement"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_anydesk_compromised_cert_feb23.yar#L38-L56"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "86f708233d5a6a46d367430dcc65b128e8dc7ec24eda774ff3860101cc16c9fc"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$sc1 = { 0D BF 15 2D EA F0 B9 81 A8 A9 38 D5 3F 76 9D B8 }
		$s2 = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
		$f1 = "AnyDesk Software GmbH" wide

	condition:
		uint16(0)==0x5a4d and filesize <20000KB and all of ($s*) and not 1 of ($f*)
}