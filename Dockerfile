FROM ubuntu:22.04

# Prevent apt from prompting for input
ENV DEBIAN_FRONTEND=noninteractive

# Install necessary packages
RUN apt update && apt install -y nano build-essential git net-tools supervisor python3 python3-pip

# Install Flask and Werkzeug
RUN python3 -m pip install flask werkzeug

# Copy flag
COPY flag.txt /home/Alex/flag.txt

#Generate Random Machine-id
RUN cat /proc/sys/kernel/random/uuid | md5sum | tr -d '-' > /etc/machine-id


# Setup app
RUN mkdir -p home/Alex/app

RUN groupadd -g 1000 Alex && \
    useradd -m -u 1000 -g Alex -s /bin/bash Alex

# Switch working environment
WORKDIR /home/Alex

# Add application
COPY challenge app/

RUN chown -R Alex:Alex /home/Alex/app

WORKDIR /home/Alex/app

# Setup supervisor  
COPY config/supervisord.conf /etc/supervisord.conf

# Expose the ports you need
EXPOSE 7777

# Run supervisord
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
