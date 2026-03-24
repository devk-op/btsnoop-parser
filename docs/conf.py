import os
import sys

sys.path.insert(0, os.path.abspath(".."))

project = "btsnoop-parser"
author = "Kranthi"
release = "0.4.0"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
]

autodoc_member_order = "bysource"
autodoc_typehints = "description"

html_theme = "sphinx_rtd_theme"
html_static_path = []
