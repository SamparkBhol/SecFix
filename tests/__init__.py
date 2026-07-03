import logging

for _n in ("httpx", "mcp", "mcp.server", "sse_starlette"):
    logging.getLogger(_n).setLevel(logging.WARNING)
