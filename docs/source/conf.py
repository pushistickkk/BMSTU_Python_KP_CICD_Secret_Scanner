# Add project root to path
import os
import sys
sys.path.insert(0, os.path.abspath('../../src'))  # ← Путь к твоему коду!

# -- General configuration ---------------------------------------------------
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',      # Для Google-style docstrings
    'sphinx.ext.viewcode',      # Ссылки на исходный код
    'sphinx.ext.intersphinx',   # Ссылки на внешнюю документацию
]

# Napoleon settings для Google-style
napoleon_google_docstring = True
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_use_ivar = True
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True

# Project info
project = 'cicd-secret-scanner'
copyright = '2026, Zhukova Mariya'
author = 'Zhukova Mariya'
release = '1.0.0'
language = 'en'