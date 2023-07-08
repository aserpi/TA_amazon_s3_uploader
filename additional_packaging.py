import shutil
import subprocess
import sys
from pathlib import Path


def additional_packaging(ta_name):
    output_path = Path("output") / ta_name
    shutil.copy(Path("LICENSE.md"), output_path)
    shutil.copy(Path("README.md"), output_path)

    # Avoid binaries without source code (Splunk Cloud check)
    subprocess.check_call([sys.executable, "-m", "pip", "install", "charset-normalizer",
                           "--no-binary=:all:", f"--target={output_path / 'lib'}", "--upgrade"])
    shutil.rmtree(output_path / "lib/bin", ignore_errors=True)

    # Patch botocore to avoid UDP connections (Splunk Cloud check)
    with open(output_path / "lib/botocore/session.py", "r") as file:
        filedata = file.read()
    filedata = filedata.replace("SOCK_DGRAM", "SOCK_STREAM")  # Force TCP connections
    with open(output_path / "lib/botocore/session.py", "w") as file:
        file.write(filedata)
