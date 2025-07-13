FROM node:20

# Create directory structure
RUN mkdir -p /sniffing_ferret/sniff

# Copy files to root directory (to match your WORKDIR)
COPY sniffing_ferret.js package*.json /

# Set working directory and install dependencies
WORKDIR /
RUN npm install

# Set the entrypoint
ENTRYPOINT ["node", "sniffing_ferret.js"]