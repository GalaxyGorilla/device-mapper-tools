#!/bin/sh
set -eu

# Minimal test runner (no pytest dependency)
python3 -m unittest discover -s tests -p 'test_*.py'
