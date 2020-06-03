FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH virustotal_static.VirusTotalStatic

# Switch to assemblyline user
USER assemblyline

# Copy VirusTotalStatic service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline