import shutil
from pathlib import Path


def additional_packaging(ta_name):
    output_path = Path("output") / ta_name
    shutil.copy(Path("LICENSE.md"), output_path)
    shutil.copy(Path("README.md"), output_path)
