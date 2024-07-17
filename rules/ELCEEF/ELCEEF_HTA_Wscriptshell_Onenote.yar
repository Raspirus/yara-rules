rule ELCEEF_HTA_Wscriptshell_Onenote : FILE
{
	meta:
		description = "Detects suspicious OneNote documents with embedded HTA + WScript.Shell"
		author = "marcin@ulikowski.pl"
		id = "8cebd862-8dfb-5f5d-befb-5c41cde945ff"
		date = "2023-02-01"
		modified = "2023-02-02"
		reference = "https://github.com/elceef/yara-rulz"
		source_url = "https://github.com/elceef/yara-rulz/blob/05834717d1464d5efce8ad9d688ff7b53886a0bb/rules/HTA_OneNote.yara#L1-L17"
		license_url = "https://github.com/elceef/yara-rulz/blob/05834717d1464d5efce8ad9d688ff7b53886a0bb/LICENSE"
		logic_hash = "0287ac5d618c9a8332d167f1a05157aa829c7e8a052c35100fcaeb644d452e5c"
		score = 65
		quality = 75
		tags = "FILE"
		hash1 = "002fe00bc429877ee2a786a1d40b80250fd66e341729c5718fc66f759387c88c"

	strings:
		$magic = { ae b1 53 78 d0 29 96 d3 }
		$hta = { 00 04 00 00 00 2e 00 68 00 74 00 61 }
		$wsh = "CreateObject(\"WScript.Shell\")"

	condition:
		filesize <5MB and $magic at 8 and $wsh and $hta
}