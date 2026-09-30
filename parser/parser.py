import re

LOG_FILE = "logs/auth.log"


patterns = [

    re.compile(
        r"(?P<timestamp>\S+ \S+) "
        r"(?P<event>Failed login) "
        r"user=(?P<username>\S+) "
        r"src_ip=(?P<source_ip>\S+) "
        r"service=(?P<service>\S+)"
    ),

    re.compile(
        r"(?P<timestamp>\S+ \S+) "
        r"(?P<event>Successful login) "
        r"user=(?P<username>\S+) "
        r"src_ip=(?P<source_ip>\S+) "
        r"service=(?P<service>\S+)"
    ),

    re.compile(
        r"(?P<timestamp>\S+ \S+) "
        r"(?P<event>Sudo command) "
        r"user=(?P<username>\S+) "
        r"src_ip=(?P<source_ip>\S+) "
        r"command=(?P<command>\S+)"
    ),

    re.compile(
        r"(?P<timestamp>\S+ \S+) "
        r"(?P<event>Account change) "
        r"user=(?P<username>\S+) "
        r"src_ip=(?P<source_ip>\S+) "
        r"action=(?P<action>\S+)"
    )
]


def parse_logs():

    events = []

    with open(LOG_FILE, "r") as file:

        for line in file:

            line = line.strip()

            matched = False

            for pattern in patterns:

                match = pattern.match(line)

                if match:

                    events.append(match.groupdict())

                    matched = True

                    break

    return events
