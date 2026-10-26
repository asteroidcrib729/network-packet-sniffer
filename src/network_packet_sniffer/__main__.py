"""Support pythonw -m network_packet_sniffer and elevated relaunches."""

from .main import main

raise SystemExit(main())
