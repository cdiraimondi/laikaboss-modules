scan_virustotal.py
================

This module uses the Virustotal API to retrieve a scan report by MD5 hash. 

**Flags Set:** s_virustotal:malicious

**Output Objects:** None

Installation
---
* Add your API key to scan_virustotal.py in the vt_api_key field.

```
def _run(self, scanObject, result, depth, args):

	vt_hit_threshold_param = int(get_option(args, 'vt_hit_threshold', 'vthitthresholdparam', 10))
	vt_api_key = "YOUR KEY GOES HERE"
```

* Modify dispatch.yara to include the module. You can simply add SCAN_VIRUSTOTAL to the scan_modules variable for any file type you want to look up
```
rule type_is_mz
{
    meta:
        scan_modules = "META_PE SCAN_VIRUSTOTAL"
        file_type = "pe"
    condition:
        uint16(0) == 0x5a4d
        and not ext_sourceModule contains "META_PE"
}


```
Testing
---
You can test this LaikaBOSS module by using laika.py and the command line switch -m. 
```
laika.py -m SCAN_VIRUSTOTAL 4174D91D0531D171A59DFD1124455AC2.danger
```

Sample output
```
"SCAN_VIRUSTOTAL": {
  "Results": {
	"hits": 37,
	"scan_date": "2017-07-21 12:37:13",
	"report_url": "https://www.virustotal.com/file/9d10f72ea425bde21082feb269d1ee337f15dbe4b339a77d6daf568d10ebabc9/analysis/1500640633/",
	"total": 58,
	"md5": "4174d91d0531d171a59dfd1124455ac2",
	"scans": {
	  "Bkav": {
		"detected": "False",
		"version": "1.3.0.9227",
		"result": "None",
		"update": "20170721"
	  },
	  "TotalDefense": {
		"detected": "False",
		"version": "37.1.62.1",
		"result": "None",
		"update": "20170721"
	  },
	  "MicroWorld-eScan": {
		"detected": "True",
		"version": "12.0.250.0",
		"result": "VB:Trojan.Valyria.661",
		"update": "20170720"
	  },
	  "nProtect": {
		"detected": "False",
		"version": "2017-07-21.02",
		"result": "None",
		"update": "20170721"
	  },
	  "CMC": {
		"detected": "False",
		"version": "1.1.0.977",
		"result": "None",
		"update": "20170721"
	  },
	  "CAT-QuickHeal": {
		"detected": "True",
		"version": "14.00",
		"result": "W97M.Downloader.BFI",
		"update": "20170721"
	  },

```
If the sample was not found on Virustotal the module output will look like:

```
"SCAN_VIRUSTOTAL": {
  "Results": "Unknown File"
},
```

Sample Flag Output
```
  "flags": [
	"s_virustotal:malicious"
  ],
```

Optional Dispatch Configuration for Virustotal Hit Threshold
---
You can configure the SCAN_VIRUSTOTAL module with an optional parameter called vt_hit_threshold that will include an 
integer value that acts as a hit threshold to determine maliciousness. If no value is set, SCAN_VIRUSTOTAL will use
a hit score of 10 or above as being deemed "malicious". An updated dispatch logic for PE files is below. In this example,
I've decided that if there are 5 or more positive hits on Virustotal for a file then I determine this to be enough to 
identify it as being malicious.

```
rule type_is_mz
{
    meta:
        scan_modules = "META_PE SCAN_VIRUSTOTAL(vt_hit_threshold=5)"
        file_type = "pe"
    condition:
        uint16(0) == 0x5a4d
        and not ext_sourceModule contains "META_PE"
}

```
