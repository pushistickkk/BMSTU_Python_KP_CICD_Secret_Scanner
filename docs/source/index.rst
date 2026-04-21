.. cicd-secret-scanner documentation master file, created by
   sphinx-quickstart on 2026.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

CI/CD Secret Scanner Documentation
===================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   modules

🔍 Overview
-----------

**CI/CD Secret Scanner** — context-aware secret scanner for CI/CD configurations.

✨ Features:
- Multi-platform: GitLab CI, GitHub Actions, Jenkins
- Multi-detector: Regex + Entropy + Contextual analysis
- Risk scoring: stage × environment × secret_type formula
- Line numbers: Exact location of each finding
- Multiple formats: Console (Rich), JSON, SARIF, Text

🚀 Quick Start
--------------

.. code-block:: bash

   # Install
   pip install -e .

   # Scan a file
   cicd-scanner scan .gitlab-ci.yml

   # Scan a directory with JSON output
   cicd-scanner scan ./ci-configs/ --format json --output results.json

📚 API Reference
----------------

See the :doc:`modules` page for detailed API documentation.

🔗 Links
--------

* `GitHub Repository <https://github.com/yourusername/cicd-secret-scanner>`_
* `Issue Tracker <https://github.com/yourusername/cicd-secret-scanner/issues>`_

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`