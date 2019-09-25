FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH alsvc_virustotal_static.virustotal_static.VirusTotalStatic

# Switch to assemblyline user
USER assemblyline

# Copy VirusTotalStatic service code
WORKDIR /opt/al/al_services/alsvc_virustotal_static
COPY . .