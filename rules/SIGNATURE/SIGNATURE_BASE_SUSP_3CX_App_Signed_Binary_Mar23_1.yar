import "pe"


rule SIGNATURE_BASE_SUSP_3CX_App_Signed_Binary_Mar23_1 : FILE
{
	meta:
		description = "Detects 3CX application binaries signed with a certificate and created in a time frame in which other known malicious binaries have been created"
		author = "Florian Roth (Nextron Systems)"
		id = "b6ce4c1d-1b7b-5e0c-af4c-05cb3ad0a4e0"
		date = "2023-03-29"
		modified = "2023-12-05"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_mal_3cx_compromise_mar23.yar#L119-L139"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3834b5ebb5a0db27a452fda1c97c921b2c9c8702505738232b15a3ed4a47dc47"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "fad482ded2e25ce9e1dd3d3ecc3227af714bdfbbde04347dbc1b21d6a3670405"
		hash2 = "dde03348075512796241389dfea5560c20a3d2a2eac95c894e7bbed5e85a0acc"

	strings:
		$sa1 = "3CX Ltd1"
		$sa2 = "3CX Desktop App" wide
		$sc1 = { 1B 66 11 DF 9C 9A 4D 6E CC 8E D5 0C 9B 91 78 73 }

	condition:
		uint16(0)==0x5a4d and pe.timestamp>1669680000 and pe.timestamp<1680108505 and all of ($sa*) and $sc1
}