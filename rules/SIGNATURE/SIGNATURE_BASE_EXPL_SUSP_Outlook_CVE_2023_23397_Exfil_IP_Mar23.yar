rule SIGNATURE_BASE_EXPL_SUSP_Outlook_CVE_2023_23397_Exfil_IP_Mar23 : CVE_2023_23397 FILE
{
	meta:
		description = "Detects suspicious .msg file with a PidLidReminderFileParameter property exploiting CVE-2023-23397 (modified delivr.to rule - more specific = less FPs but limited to exfil using IP addresses, not FQDNs)"
		author = "delivr.to, Florian Roth, Nils Kuhnert, Arnim Rupp, marcin@ulikowski.pl"
		id = "d85bf1d9-aebe-5f8c-9dd4-c509f64e221a"
		date = "2023-03-15"
		modified = "2023-03-18"
		reference = "https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_outlook_cve_2023_23397.yar#L39-L79"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "47fee24586cd2858cfff2dd7a4e76dc95eb44c8506791ccc2d59c837786eafe3"
		hash = "582442ee950d546744f2fa078adb005853a453e9c7f48c6c770e6322a888c2cf"
		hash = "6c0087a5cbccb3c776a471774d1df10fe46b0f0eb11db6a32774eb716e1b7909"
		hash = "7fb7a2394e03cc4a9186237428a87b16f6bf1b66f2724aea1ec6a56904e5bfad"
		hash = "eedae202980c05697a21a5c995d43e1905c4b25f8ca2fff0c34036bc4fd321fa"
		hash = "e7a1391dd53f349094c1235760ed0642519fd87baf740839817d47488b9aef02"
		logic_hash = "a8e8326f5aaa29b449f9203623e03d3d3a1d176bb764171d860afc510a1732e6"
		score = 75
		quality = 85
		tags = "CVE-2023-23397, FILE"

	strings:
		$psetid_app = { 02 20 06 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
		$psetid_meeting = { 90 DA D8 6E 0B 45 1B 10 98 DA 00 AA 00 3F 13 05 }
		$psetid_task = { 03 20 06 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$rfp = { 1F 85 00 00 }
		$u1 = { 5C 00 5C 00 (3? 00 2E|3? 00 3? 00 2E|3? 00 3? 00 3? 00 2E) 00 (3? 00 2E|3? 00 3? 00 2E|3? 00 3? 00 3? 00 2E) 00 (3? 00 2E|3? 00 3? 00 2E|3? 00 3? 00 3? 00 2E) 00 (3? 00 3? 00 3? 00|3? 00 3? 00|3? 00) }
		$u2 = { 00 5C 5C (3? 2E|3? 3? 2E|3? 3? 3? 2E) (3? 2E|3? 3? 2E|3? 3? 3? 2E) (3? 2E|3? 3? 2E|3? 3? 3? 2E) (3? 3? 3?|3? 3?|3?) }
		$fp_msi1 = {84 10 0C 00 00 00 00 00 C0 00 00 00 00 00 00 46}

	condition:
		( uint16(0)==0xCFD0 and 1 of ($psetid*) or uint32be(0)==0x789F3E22) and any of ($u*) and $rfp and not 1 of ($fp*)
}