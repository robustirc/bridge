# Start with busybox, but with libc.so.6
FROM debian:wheezy

MAINTAINER Michael Stapelberg <michael@robustirc.net>

# So that we can run as unprivileged user inside the container.
RUN sed -i '/^nobody/d' /etc/passwd
RUN echo 'nobody:x:99:99:nobody:/:/bin/sh' >> /etc/passwd

RUN apt-get update && apt-get install -y stunnel4

USER nobody

ADD robustirc-bridge.conf /etc/stunnel/robustirc-bridge.conf

EXPOSE 6697

# The following flags have to be specified when starting this container:
# -network
# Refer to -help for documentation on them.
ENTRYPOINT ["/usr/bin/stunnel4", "/etc/stunnel/robustirc-bridge.conf"]
