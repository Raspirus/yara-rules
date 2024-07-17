import "pe"


rule DITEKSHEN_INDICATOR_RMM_Meshagent : FILE
{
	meta:
		description = "Detects MeshAgent. Review RMM Inventory"
		author = "ditekSHen"
		id = "3d0baa87-22c9-569d-ba84-37ccaac577b8"
		date = "2023-11-16"
		modified = "2023-11-16"
		reference = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_rmm.yar#L3-L27"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "f36c0e23b20e4466100cf4ea2a91515bf1d54505e7b1f0926a4e416a04e0dbcf"
		score = 75
		quality = 75
		tags = "FILE"
		clamav1 = "INDICATOR.Win.RMM.MeshAgent"

	strings:
		$x1 = "\\MeshAgent" wide
		$x2 = "Mesh Agent" wide
		$x3 = "MeshDummy" wide
		$x4 = "MeshCentral" wide
		$x5 = "ILibRemoteLogging.c" ascii
		$x6 = "AgentCore/MeshServer_" wide
		$s1 = "var _tmp = 'Detected OS: ' + require('os').Name;" ascii
		$s2 = "console.log(getSHA384FileHash(process.execPath).toString('hex'))" ascii
		$s3 = "ScriptContainer.Create(): Error spawning child process, using [%s]" fullword ascii
		$s4 = "{\"agent\":\"" ascii
		$s6 = "process.versions.commitHash" fullword ascii
		$s7 = "console.log('Error Initializing script from Zip file');process._exit();" fullword ascii

	condition:
		uint16(0)==0x5a4d and (3 of ($x*) or (1 of ($x*) and 3 of ($s*)) or 6 of ($s*))
}