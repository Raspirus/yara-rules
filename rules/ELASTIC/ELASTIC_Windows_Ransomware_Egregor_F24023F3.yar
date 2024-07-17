rule ELASTIC_Windows_Ransomware_Egregor_F24023F3 : BETA FILE MEMORY
{
	meta:
		description = "Identifies EGREGOR (Sekhemt) ransomware"
		author = "Elastic Security"
		id = "f24023f3-c887-42fc-8927-cdbd04b5f84f"
		date = "2020-10-15"
		modified = "2021-08-23"
		reference = "https://www.bankinfosecurity.com/egregor-ransomware-adds-to-data-leak-trend-a-15110"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Egregor.yar#L1-L25"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "5695b44f6ce018a91a99b6c94feae740ff4ac187e232bc9044e51d62d1f42bfa"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "3a82a548658e0823678ec9d633774018ddc6588f5e2fbce74826a46ce9c43c40"
		threat_name = "Windows.Ransomware.Egregor"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "M:\\sc\\p\\testbuild.pdb" ascii fullword
		$a2 = "C:\\Logmein\\{888-8888-9999}\\Logmein.log" wide fullword
		$a3 = "nIcG`]/h3kpJ0QEAC5OJC|<eT}}\\5K|h\\\\v<=lKfHKO~01=Lo0C03icERjo0J|/+|=P0<UeN|e2F@GpTe]|wpMP`AG+IFVCVbAErvTeBRgUN1vQHNp5FVtc1WVi/G"
		$a4 = "pVrGRgJui@6ejnOu@4KgacOarSh|firCToW1LoF]7BtmQ@2j|hup2owUHQ6W}\\U3gwV6OwSPTMQVq2|G=GKrHpjOqk~`Ba<qu\\2]r0RKkf/HGngsK7LhtvtJiR}+4J"
		$a5 = "Your network was ATTACKED, your computers and servers were LOCKED," ascii wide
		$a6 = "Do not redact this special technical block, we need this to authorize you." ascii wide

	condition:
		2 of ($a*)
}