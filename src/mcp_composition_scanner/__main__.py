"""Allow running as: python -m mcp_composition_scanner"""

from .composition_analyser import main
import asyncio

asyncio.run(main())
