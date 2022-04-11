import base64
import json
import time
from typing import Dict, Any
from vt import Client, APIError

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, Classification, BODY_FORMAT

MAX_RETRY = 3


class AvHitSection(ResultSection):
    def __init__(self, av_name, virus_name):
        title = f'{av_name} identified the file as {virus_name}'
        json_body = dict(
            av_name=av_name,
            virus_name=virus_name,
        )
        super(AvHitSection, self).__init__(
            title_text=title,
            classification=Classification.UNRESTRICTED,
            body_format=BODY_FORMAT.KEY_VALUE,
            body=json.dumps(json_body),
        )


class VirusTotalStatic(ServiceBase):
    def __init__(self, config=None):
        super(VirusTotalStatic, self).__init__(config)
        self.client = None

    def start(self):
        self.log.debug("VirusTotalStatic service started")

    def execute(self, request: ServiceRequest):
        try:
            self.client = Client(apikey=self.config.get("api_key", request.get_param("api_key")),
                                 proxy=self.config.get('proxy') or None)
        except Exception as e:
            self.log.error("No API key found for VirusTotal")
            raise e

        if request.task.metadata.get('submitted_url', None) and request.task.depth == 0:
            response = self.scan_url(request)
        else:
            response = self.scan_file(request)
        if response:
            result = self.parse_results(response)
            request.result = result
        else:
            request.result = Result()

    def common_scan(self, type: str, sample, retried: int = 0):
        json_response = None
        if retried < MAX_RETRY:
            try:
                json_response = self.client.get_json(f"/{type}s/{sample}")
            except APIError as e:
                if "NotFoundError" in e.code:
                    self.log.warning(f"VirusTotal has nothing on this {type}.")
                elif "QuotaExceededError" in e.code:
                    self.log.warning("Quota Exceeded. Trying again in 60s")
                    time.sleep(60)
                    retried += 1
                    return self.common_scan(type, sample, retried)
                else:
                    self.log.error(e)
        return json_response

    def scan_file(self, request: ServiceRequest):
        return self.common_scan("file", request.sha256)

    def scan_url(self, request: ServiceRequest):
        url_id = base64.urlsafe_b64encode(request.task.metadata.get('submitted_url').encode()).decode().strip("=")
        return self.common_scan("url", url_id)

    @staticmethod
    def parse_results(response: Dict[str, Any]):
        res = Result()
        response = response['data']

        url_section = ResultSection('VirusTotal report permalink',
                                    body_format=BODY_FORMAT.URL,
                                    body=json.dumps({"url": response['links']['self']}))
        res.add_section(url_section)
        response = response['attributes']
        scans = response['last_analysis_results']
        av_hits = ResultSection('Anti-Virus Detections')
        av_hits.add_line(f'Found {response["last_analysis_stats"]["malicious"]} AV hit(s) from '
                         f'{len(response["last_analysis_results"].keys())}')
        for majorkey, subdict in sorted(scans.items()):
            if subdict['category'] == "malicious":
                virus_name = subdict['result']
                av_hit_section = AvHitSection(majorkey, virus_name)
                av_hit_section.set_heuristic(1, signature=f'{majorkey}.{virus_name}')
                av_hit_section.add_tag('av.virus_name', virus_name)
                av_hits.add_subsection(av_hit_section)

        res.add_section(av_hits)

        return res
