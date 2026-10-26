"""Static entry point for the windowed PyInstaller bundle."""

from network_packet_sniffer.main import main

if __name__ == "__main__":
    raise SystemExit(main())
