# DEPRECATED: Replaced by [assemblyline-service-virustotal](https://github.com/CybercentreCanada/assemblyline-service-virustotal)

# VirusTotal Static Service

This Assemblyline service performs a hash check against the VirusTotal API and returns the results.

**NOTE**: This service **requires** you to have your own API key (Paid or Free). It is **not** preinstalled during a default installation.

## Execution

This service calls the [VirusTotal file report API](https://developers.virustotal.com/v3.0/reference#file-info) with the hash of your file and returns the results (if any) over the v3 REST API.

Because this service queries an external API, if selected by the user, it will prompt the user and notify them that their file or metadata related to their file will leave our system.
