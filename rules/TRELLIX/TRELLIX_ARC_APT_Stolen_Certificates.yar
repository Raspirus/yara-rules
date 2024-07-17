import "pe"


rule TRELLIX_ARC_APT_Stolen_Certificates : BACKDOOR FILE
{
	meta:
		description = "Rule to detect samples digitally signed from these stolen certificates"
		author = "Marc Rivero | McAfee ATR Team"
		id = "57051977-780c-5c8e-bc66-0f1d8b3bbd93"
		date = "2020-04-17"
		modified = "2020-08-14"
		reference = "https://www.blackberry.com/content/dam/blackberry-com/asset/enterprise/pdf/direct/report-bb-decade-of-the-rats.pdf"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_decade_of_RATs.yar#L196-L221"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "ce3424524fd1f482a0339a3f92e440532cff97c104769837fa6ae52869013558"
		logic_hash = "9b700e4889349d0203bdd4e00035ee9c9aba5025ccc57eef915b2c78996f8160"
		score = 75
		quality = 70
		tags = "BACKDOOR, FILE"
		rule_version = "v1"
		malware_type = "backdoor"
		malware_family = "Backdoor:W32/Pwnlnx"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "/C=KR/ST=Seoul/L=Gangnam-gu/O=LivePlex Corp/CN=LivePlex Corp" and pe.signatures[i].serial=="3f:55:42:e2:e7:1d:8d:b3:57:04:1c:9d:d4:5b:95:0a" or pe.signatures[i].subject contains "/C=KR/ST=Seoul/L=Gangnam-gu/O=LivePlex Corp/CN=LivePlex Corp" and pe.signatures[i].serial=="3f:55:42:e2:e7:1d:8d:b3:57:04:1c:9d:d4:5b:95:0a" or pe.signatures[i].subject contains "/C=KR/ST=Seoul/L=Gangnam-gu/O=LivePlex Corp/CN=LivePlex Corp" or pe.signatures[i].serial=="3f:55:42:e2:e7:1d:8d:b3:57:04:1c:9d:d4:5b:95:0a")
}