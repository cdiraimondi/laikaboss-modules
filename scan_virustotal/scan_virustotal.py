# Copyright 2017 Chuck DiRaimondi
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from laikaboss.objectmodel import ExternalVars, ModuleObject, ScanError
from laikaboss.si_module import SI_MODULE
from laikaboss.util import get_option
import hashlib
import requests


class SCAN_VIRUSTOTAL(SI_MODULE):
    def __init__(self):
        self.module_name = "SCAN_VIRUSTOTAL"

    def _run(self, scanObject, result, depth, args):

        vt_hit_threshold_param = int(get_option(args, 'vt_hit_threshold', 'vthitthresholdparam', 10))
        vt_api_key = "YOUR KEY GOES HERE"

        moduleResult = []
        vt_results = {}

        try:
            md5 = hashlib.md5(scanObject.buffer).hexdigest()

            params = {'apikey': vt_api_key,
                      'resource': md5}
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
            json_response = response.json()
            if json_response['response_code'] == 1:
                scan_date = json_response['scan_date']
                md5 = json_response['md5']
                total_submissions = json_response['total']
                total_positives = json_response['positives']
                report_url = json_response['permalink']
                scans = json_response['scans']

                vt_results['scan_date'] = scan_date
                vt_results['md5'] = md5
                vt_results['hits'] = total_positives
                vt_results['total'] = total_submissions
                vt_results['report_url'] = report_url
                vt_results['scans'] = scans

                if total_positives >= vt_hit_threshold_param:
                    scanObject.addFlag('s_virustotal:malicious')

                scanObject.addMetadata(self.module_name, "Results", vt_results)
            else:
                scanObject.addMetadata(self.module_name, "Results", "Unknown File")
        except ScanError:
            raise

        return moduleResult
