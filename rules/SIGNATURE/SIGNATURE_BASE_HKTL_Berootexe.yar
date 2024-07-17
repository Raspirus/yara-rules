import "pe"


rule SIGNATURE_BASE_HKTL_Berootexe : FILE
{
	meta:
		description = "Detects beRoot.exe which checks common Windows missconfigurations"
		author = "yarGen Rule Generator"
		id = "b91c2e0b-2e47-5339-bf48-eaa8329ea63b"
		date = "2018-07-25"
		modified = "2023-12-05"
		reference = "https://github.com/AlessandroZ/BeRoot/tree/master/Windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4431-L4447"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8e10fddd3b3eb5e5200d9ed0bcb23961d196d9e1de03ebf03a96374ee02a9097"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "865b3b8ec9d03d3475286c3030958d90fc72b21b0dca38e5bf8e236602136dd7"

	strings:
		$s1 = "checks.webclient.secretsdump(" ascii
		$s2 = "beroot.modules" fullword ascii
		$s3 = "beRoot.exe.manifest" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <18000KB and 1 of them )
}