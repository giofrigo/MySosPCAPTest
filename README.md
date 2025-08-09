# PCAP Analyzer

This application analyzes SIP calls and RTP packets in a PCAP file. It extracts call details, calculates durations, counts RTP packets, and outputs a summary.

## Features

- Lists all SIP calls with their Call-ID
- Shows final status (Hanged up, Cancelled, Unknown)
- Calculates call duration (INVITE to BYE/CANCEL)
- Counts RTP packets per call
- Outputs results to the console
- Ready to run in Docker

## Requirements

- Docker (optional, for containerized usage)

## Usage

###  Run in Docker

#### Build the Docker image

Make sure your `Dockerfile`, `pcapnaitor.py`, and PCAP file are in the same directory.

```sh
docker build -t pcapnaitor .
```

#### Run the container

If the PCAP file is inside the image:
```sh
docker run --rm pcapnaitor
```

If you want to mount the PCAP file from your host: (TODO)
```sh
docker run --rm -v %cd%:/app pcapnaitor assignment.pcap
```
## Output

The application prints a summary for each call:
- Call-ID
- Status
- Duration
- RTP packet count

And the total number of SIP calls.
