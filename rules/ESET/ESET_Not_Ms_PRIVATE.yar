import "pe"

private rule ESET_Not_Ms_PRIVATE
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "7edb96a1-a63a-580e-ac26-66fa14ae97d1"
		date = "2018-09-05"
		modified = "2018-09-05"
		reference = "https://github.com/eset/malware-ioc"
		source_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/turla/turla-outlook.yar#L34-L40"
		license_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/LICENSE"
		logic_hash = "71f492eaa80bee5e8cc5bec67b2a7fd6f5f71ee2594d9f531043747533c80443"
		score = 75
		quality = 80
		tags = ""

	condition:
		not for any i in (0..pe.number_of_signatures-1) : (pe.signatures[i].issuer contains "Microsoft Corporation")
}