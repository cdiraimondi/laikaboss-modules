from laikaboss.objectmodel import ExternalVars, ModuleObject, ScanError
from laikaboss.si_module import SI_MODULE
from laikaboss import config
import tempfile
import os
import isoparser
import hashlib

class EXPLODE_ISO(SI_MODULE):
    def __init__(self):
        self.module_name = "EXPLODE_ISO"

        self.TEMP_DIR = '/tmp/laikaboss_tmp'
        if hasattr(config, 'tempdir'):
            self.TEMP_DIR = config.tempdir.rstrip('/')
        if not os.path.isdir(self.TEMP_DIR):
            os.mkdir(self.TEMP_DIR)
            os.chmod(self.TEMP_DIR, 0777)

    def _run(self, scanObject, result, depth, args):

        moduleResult = []
        try:

            # Create a temp file so isoparser has a file to analyze
            with tempfile.NamedTemporaryFile(dir=self.TEMP_DIR) as temp_file_input:
                temp_file_input_name = temp_file_input.name
                temp_file_input.write(scanObject.buffer)
                temp_file_input.flush()

                # Create an iso object
                iso = isoparser.parse(temp_file_input_name)

                # Loop through iso and identify child object. Write each child object to output directory
                for child in iso.root.children:
                    child_md5 = hashlib.md5(child.content).hexdigest()
                    moduleResult.append(ModuleObject(buffer=child.content, externalVars=ExternalVars(filename='e_iso_%s' % child_md5)))

        except ScanError:
            raise

        return moduleResult
