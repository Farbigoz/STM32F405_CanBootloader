import os
import sys
import struct

from typing import Union


def FindChaiLib() -> Union[None, str]:
    # Windows
    if sys.platform.startswith("win"):
        programFilesPath = os.getenv("PROGRAMFILES(X86)")
        for programFolder in os.listdir(programFilesPath):
            if programFolder.startswith("CHAI-"):
                chaiPath = os.path.join(programFilesPath, programFolder)

                if struct.calcsize("P") * 8 == 64 and "x64" in os.listdir(chaiPath):
                    path = os.path.join(chaiPath, "x64", "CHAI.dll")

                elif struct.calcsize("P") * 8 == 32 and "x32" in os.listdir(chaiPath):
                    path = os.path.join(chaiPath, "x32", "CHAI.dll")

                elif struct.calcsize("P") * 8 == 32:
                    path = os.path.join(chaiPath, "lib", "CHAI.dll")

                else:
                    return None

                if os.path.exists(path):
                    return path

    # TODO: Linux

    return None
