rule SIGNATURE_BASE_APT_NK_AR18_165A_Hiddencobra_Import_Deob : HIDDEN_COBRA TYPEFRAME FILE
{
	meta:
		description = "Hidden Cobra - Detects installed proxy module as a service"
		author = "NCCIC trusted 3rd party - Edit: Tobias Michalski"
		id = "f403d589-be35-57a7-9675-f92657c11acc"
		date = "2018-04-12"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/analysis-reports/AR18-165A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ar18_165a.yar#L43-L60"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "ae769e62fef4a1709c12c9046301aa5d"
		hash = "e48fe20eblf5a5887f2ac631fed9ed63"
		logic_hash = "2eff83738ca4f2db8327c1ee2a9539d7ce882a315025a656d391c16079e432cb"
		score = 75
		quality = 85
		tags = "HIDDEN_COBRA, TYPEFRAME, FILE"
		incident = "10135536"
		category = "hidden_cobra"
		family = "TYPEFRAME"

	strings:
		$ = { 8a 01 3c 62 7c 0a 3c 79 7f 06 b2 db 2a d0 88 11 8a 41 01 41 84 c0 75 e8}
		$ = { 8A 08 80 F9 62 7C 0B 80 F9 79 7F 06 82 DB 2A D1 88 10 8A 48 01 40 84 C9 75 E6}

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and any of them
}