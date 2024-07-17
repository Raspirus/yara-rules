
rule SECUINFRA_DROPPER_Valyria_Stage_1 : JAVASCRIPT VBS VALYRIA FILE
{
	meta:
		description = "Family was taken from VirusTotal"
		author = "SECUINFRA Falcon Team"
		id = "7e2ab9db-142c-5dee-92b7-4a70d747c540"
		date = "2022-02-18"
		modified = "2022-02-18"
		reference = "https://bazaar.abuse.ch/sample/c8a8fea3cbe08cd97e56a0e0dbc59a892f8ab1ff3b5217ca3c9b326eeee6ca66/"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Dropper/valyria.yar#L1-L23"
		license_url = "N/A"
		logic_hash = "94643123a4be26c818d43a77b907edf8651d306463f4df750db67cef790f10eb"
		score = 75
		quality = 70
		tags = "JAVASCRIPT, VBS, VALYRIA, FILE"

	strings:
		$a1 = "<script language=\"vbscript\">"
		$a2 = "<script language=\"javascript\">"
		$b1 = "window.resizeTo(0,0);"
		$b2 = ".Environment"
		$b3 = ".item().Name"
		$b4 = "v4.0.30319"
		$b5 = "v2.0.50727"
		$c1 = "Content Writing.docx"
		$c2 = "eval"

	condition:
		filesize <600KB and all of ($a*) and 3 of ($b*) and 1 of ($c*)
}