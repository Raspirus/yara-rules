rule JPCERTCC_Elf_Wellmess : FILE
{
	meta:
		description = "ELF_Wellmess"
		author = "JPCERT/CC Incident Response Group"
		id = "3e6cb461-fc51-5ea6-bd6f-6dab11d5704c"
		date = "2021-08-16"
		modified = "2021-08-16"
		reference = "https://github.com/JPCERTCC/MalConfScan/"
		source_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/yara/rule.yara#L571-L584"
		license_url = "https://github.com/JPCERTCC/MalConfScan//blob/19ec0d145535a6a4cfd37c0960114f455a8c343e/LICENSE.txt"
		hash = "00654dd07721e7551641f90cba832e98c0acb030e2848e5efc0e1752c067ec07"
		logic_hash = "99789bba9c398b7927b3ab42bb4df40e5470e0816cc048dcc7d09c6a78a1a505"
		score = 75
		quality = 80
		tags = "FILE"

	strings:
		$botlib1 = "botlib.wellMess" ascii
		$botlib2 = "botlib.Command" ascii
		$botlib3 = "botlib.Download" ascii
		$botlib4 = "botlib.AES_Encrypt" ascii

	condition:
		( uint32(0)==0x464C457F) and all of ($botlib*)
}