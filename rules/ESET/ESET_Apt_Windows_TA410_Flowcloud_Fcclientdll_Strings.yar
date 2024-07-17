import "pe"


rule ESET_Apt_Windows_TA410_Flowcloud_Fcclientdll_Strings : FILE
{
	meta:
		description = "Strings found in fcClientDll/responsor.dat module."
		author = "ESET Research"
		id = "80ecaf51-406f-590c-8f9c-59672683de02"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/ta410/ta410.yar#L641-L669"
		license_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/LICENSE"
		logic_hash = "3a93f58cf14b57a96157077ec14aa6fb181e3da80f4ba46c0379a58b67c08a0e"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "http://%s/html/portlet/ext/draco/resources/draco_manager.swf/[[DYNAMIC]]/1"
		$s2 = "Cookie: COOKIE_SUPPORT=true; JSESSIONID=5C7E7A60D01D2891F40648DAB6CB3DF4.jvm1; COMPANY_ID=10301; ID=666e7375545678695645673d; PASSWORD=7a4b48574d746470447a303d; LOGIN=6863303130; SCREEN_NAME=4a2b455377766b657451493d; GUEST_LANGUAGE_ID=en-US"
		$fc_msg = ".fc_net.msg"
		$s4 = "\\pipe\\namedpipe_keymousespy_english" wide
		$s5 = "8932910381748^&*^$58876$%^ghjfgsa413901280dfjslajflsdka&*(^7867=89^&*F(^&*5678f5ds765f76%&*%&*5"
		$s6 = "cls_{CACB140B-0B82-4340-9B05-7983017BA3A4}" wide
		$s7 = "HTTP/1.1 200 OK\x0d\nServer: Apache-Coyote/1.1\x0d\nPragma: No-cache\x0d\nCache-Control: no-cache\x0d\nExpires: Thu, 01 Jan 1970 08:00:00 CST\x0d\nLast-Modified: Fri, 27 Apr 2012 08:11:04 GMT\x0d\nContent-Type: application/xml\x0d\nContent-Length: %d\x0d\nDate: %s GMT"
		$sql1 = "create table if not exists table_filed_space"
		$sql2 = "create table if not exists clipboard"
		$sql3 = "create trigger if not exists file_after_delete after delete on file"
		$sql4 = "create trigger if not exists file_data_after_insert after insert on file_data"
		$sql5 = "create trigger if not exists file_data_after_delete after delete on file_data"
		$sql6 = "create trigger if not exists file_data_after_update after update on file_data"
		$sql7 = "insert into file_data(file_id, ofs, data, status)"

	condition:
		uint16(0)==0x5a4d and ( any of ($s*) or #fc_msg>=8 or 4 of ($sql*))
}