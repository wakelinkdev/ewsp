"""
pytest configuration for EWSP Core tests.
"""

import sys
from pathlib import Path

# Add bindings directory to path
bindings_dir = Path(__file__).parent.parent
sys.path.insert(0, str(bindings_dir))
