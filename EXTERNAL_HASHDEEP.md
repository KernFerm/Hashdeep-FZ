# External Hashdeep setup

The companion runs genuine Hashdeep on Raspberry Pi OS or another Linux system. A Pi is not required; a spare Linux laptop, desktop, mini PC, or VM works if it can access a 3.3 V UART adapter.

## Install software

Install Hashdeep from your distribution when available:

```sh
sudo apt update
sudo apt install hashdeep python3 python3-venv
sudo mkdir -p /opt/hashdeep-fz /var/lib/hashdeep-fz/input /var/lib/hashdeep-fz/output
sudo cp companion/hashdeep_fz_bridge.py /opt/hashdeep-fz/
sudo python3 -m venv /opt/hashdeep-fz/venv
sudo /opt/hashdeep-fz/venv/bin/pip install -r companion/requirements.txt
sudo chown -R "$USER":dialout /var/lib/hashdeep-fz
```

If the distribution lacks Hashdeep, build the pinned upstream revision recorded in UPSTREAM_VERSION.md and install its executable as `/usr/local/bin/hashdeep`. The bridge intentionally accepts no executable path from UART or command-line input.

## Wire safely

Connect Flipper GPIO USART TX to adapter RX, USART RX to adapter TX, and GND to GND. Logic must be 3.3 V. Do not connect a 5 V TTL TX pin or power rails unless the adapter/device documentation explicitly requires and supports it.

Find the adapter, commonly `/dev/ttyUSB0` or `/dev/ttyACM0`, then grant the user serial access:

```sh
sudo usermod -aG dialout "$USER"
```

Log out and back in after changing groups.

## Run

```sh
/opt/hashdeep-fz/venv/bin/python /opt/hashdeep-fz/hashdeep_fz_bridge.py \
  --port /dev/ttyUSB0 --baud 115200
```

Put real input files in `/var/lib/hashdeep-fz/input`. Results use:

- recursive hash report: `/var/lib/hashdeep-fz/output/hashdeep-report.txt`
- known manifest: `/var/lib/hashdeep-fz/known.hashdeep`
- audit report: `/var/lib/hashdeep-fz/output/hashdeep-report.txt`

The bridge writes `.partial` first and atomically replaces the result only after a non-cancelled run. Cancellation deletes partial output.

## Full Hashdeep functionality

The Flipper screen starts the safe recursive hash operation. Create/audit operations exist in HDF1, and advanced upstream options are available directly on Linux, for example:

```sh
hashdeep -r /var/lib/hashdeep-fz/input > /var/lib/hashdeep-fz/known.hashdeep
hashdeep -a -k /var/lib/hashdeep-fz/known.hashdeep -r /var/lib/hashdeep-fz/input
```

These commands are genuine Hashdeep. Consult upstream documentation for options and use only on authorized data.
