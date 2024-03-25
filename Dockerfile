FROM ubuntu:20.04

# Prevent apt from prompting for input
ENV DEBIAN_FRONTEND=noninteractive

# Install necessary packages
RUN apt update && apt install -y nano lsb-release gcc screen make build-essential git net-tools python3 python3-pip

# Install Flask and Werkzeug
RUN python3 -m pip install flask werkzeug

# Copy flag
COPY flag.txt /root/flag

#add user
RUN adduser -D -u 1000 -g 1000 -s /bin/sh www

# Setup app
RUN mkdir -p /app

# Switch working environment
WORKDIR /app

# Add application
COPY challenge .
RUN chown -R www: /app

# Setup supervisor
COPY config/supervisord.conf /etc/supervisord.conf

# Expose the ports you need
EXPOSE 7777

# Run supervisord
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
