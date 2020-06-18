"""
Copyright 2019 Southern California Edison
Copyright 2019 Pacific Gas and Electric Company

ALL RIGHTS RESERVED
"""

import uuid

try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse
import json
import requests

class GlobalSettings:
    name = "PacketCap"
    SNIFFER_INTERFACE = "en4"
    API_HOST = "192.168.81.250"
    API_PORT = "443"
    BASE_URL = urlparse.urlunparse(['https', API_HOST] + [''] * 4)

    EXCLUDED_PROTOCOLS = [
        "_ws.expert",
        "_ws.lua",
        "_ws.malformed",
        "_ws.number_string.decoding_error",
        "_ws.short",
        "_ws.type_length",
        "_ws.unreassembled",
        "image-gif",
        "image-jfif",
        "media",
        "png",
        "xml",
        "zip"
    ]

    FIM_CONFIG = {
        "configuration": [
            {"path": "/tmp/fimd_file_testing",
             "files": ["foo.exe", "bar.exe", "bar.config", "baz.exe"]
             },
            {"path": "/tmp/fimd_path_testing",
             "files": "null"
             }
        ]
    }

    _devuuid = "71b4d7d9-daf1-4ae0-9027-706c3d88d4af"


    def get_devuuid(self, online=False):
        if self._devuuid is not None:
            return self._devuuid
        else:
            self._devuuid = str(uuid.uuid4())
        return self._devuuid
