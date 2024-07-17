rule SIGNATURE_BASE_HKTL_Shellpop_Ruby : FILE
{
	meta:
		description = "Detects suspicious ruby shellpop"
		author = "Tobias Michalski"
		id = "cb3a93d5-02a1-5a49-b37e-3f9312b993ea"
		date = "2018-05-18"
		modified = "2023-12-05"
		reference = "https://github.com/0x00-0x00/ShellPop"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4251-L4263"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "aa076540ef01d04117d3340f4d84c21f79acfc558ed4aa585d801b6a6bc797a2"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "6b425b37f3520fd8c778928cc160134a293db0ce6d691e56a27894354b04f783"

	strings:
		$x1 = ");while(cmd=c.gets);IO.popen(cmd,'r'){" ascii

	condition:
		filesize <1KB and all of them
}