
rule SIGNATURE_BASE_Generic_Shellcode_Downloader_Specific : FILE
{
	meta:
		description = "Detects Doorshell from NCSC report"
		author = "NCSC"
		id = "ddd25add-ff84-5106-ac3c-5d5b4c1ef2a9"
		date = "2018-04-06"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ncsc_report_04_2018.yar#L73-L89"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "b8bc0611a7fd321d2483a0a9a505251e15c22402e0cfdc62c0258af53ed3658a"
		logic_hash = "9315ad03b5a28030c32fea5547db3ae421a1ebdae0b96a8a4c2f92660c41bc40"
		score = 75
		quality = 79
		tags = "FILE"

	strings:
		$push1 = {68 6C 6C 6F 63}
		$push2 = {68 75 61 6C 41}
		$push3 = {68 56 69 72 74}
		$a = {BA 90 02 00 00 46 C1 C6 19 03 DD 2B F4 33 DE}
		$b = {87 C0 81 F2 D1 19 89 14 C1 C8 1F FF E0}

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3C))==0x4550) and ($a or $b) and @push1<@push2 and @push2<@push3
}