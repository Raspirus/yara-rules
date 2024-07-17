import "pe"


rule SIGNATURE_BASE_HKTL_Shellpop_Netcat_UDP : FILE
{
	meta:
		description = "Detects suspicious netcat popshell"
		author = "Tobias Michalski"
		id = "67aa53b6-00bc-5d2e-b6f3-37e9121cdd01"
		date = "2018-05-18"
		modified = "2023-12-05"
		reference = "https://github.com/0x00-0x00/ShellPop"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4280-L4293"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0c85b1275ccf5bbc7f6e0ab0f1fa9d1bce7d56912411f84f9946163191c79576"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "d823ad91b315c25893ce8627af285bcf4e161f9bbf7c070ee2565545084e88be"

	strings:
		$s1 = "mkfifo fifo ; nc.traditional -u" ascii
		$s2 = "< fifo | { bash -i; } > fifo" fullword ascii

	condition:
		filesize <1KB and 1 of them
}