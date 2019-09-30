FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH virustotal_static.VirusTotalStatic

# Switch to assemblyline user
USER assemblyline

# Copy VirusTotalStatic service code
WORKDIR /opt/al_service
COPY . .