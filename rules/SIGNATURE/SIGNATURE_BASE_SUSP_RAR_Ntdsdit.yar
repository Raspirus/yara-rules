rule SIGNATURE_BASE_SUSP_RAR_Ntdsdit : FILE
{
	meta:
		description = "Detects suspicious RAR file that contains ntds.dit or SAM export"
		author = "Florian Roth (Nextron Systems)"
		id = "da9e160f-3213-5027-bb0f-bf80ab3d5318"
		date = "2019-12-16"
		modified = "2022-11-15"
		reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_rar_exfil.yar#L2-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "12e527b040e02f573f2a6e0fac4ff99ec441bf189c9bb7e1f763619c079a5bfa"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "ntds.dit0" ascii fullword
		$x2 = { 0? 53 41 4D 30 01 00 03 }
		$x3 = { 0? 73 61 6D 30 01 00 03 }

	condition:
		uint32(0)==0x21726152 and 1 of them
}