import "pe"


rule SIGNATURE_BASE_HKTL_Shellpop_Awk : FILE
{
	meta:
		description = "Detects suspicious AWK Shellpop"
		author = "Tobias Michalski"
		id = "92d1e6dd-d758-5df2-b5e5-eb275964551d"
		date = "2018-05-18"
		modified = "2023-12-05"
		reference = "https://github.com/0x00-0x00/ShellPop"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4265-L4278"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7d676ffbd1ce083a1b8e34576125fb0805caef4423089cd72a92483467669b78"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "7513a0a0ba786b0e22a9a7413491b4011f60af11253c596fa6857fb92a6736fc"

	strings:
		$s1 = "awk 'BEGIN {s = \"/inet/tcp/0/" ascii
		$s2 = "; while(42) " ascii

	condition:
		filesize <1KB and 1 of them
}