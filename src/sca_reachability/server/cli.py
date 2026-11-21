import argparse
import uvicorn


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serve the SCA branch-monitoring dashboard.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    uvicorn.run(
        "sca_reachability.server.app:create_app",
        factory=True, host=args.host, port=args.port,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
