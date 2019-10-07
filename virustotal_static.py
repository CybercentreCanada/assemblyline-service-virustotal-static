import json
from typing import Dict, Any

import requests

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, Classification, BODY_FORMAT


class VTException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class AvHitSection(ResultSection):
    def __init__(self, av_name, virus_name):
        title = f'{av_name} identified the file as {virus_name}'
        super(AvHitSection, self).__init__(
            title_text=title,
            classification=Classification.UNRESTRICTED)


class VirusTotalStatic(ServiceBase):
    def __init__(self, config=None):
        super(VirusTotalStatic, self).__init__(config)
        self.api_key = self.config.get("api_key", None)

    def start(self):
        self.log.debug("VirusTotalStatic service started")

    def execute(self, request: ServiceRequest):
        response = self.scan_file(request)
        result = self.parse_results(response)
        request.result = result

    def scan_file(self, request: ServiceRequest):
        api_key = None
        try:
            api_key = request.get_param('api_key')
        except Exception:  # submission parameter not found
            pass

        # Check to see if the file has been seen before
        url = self.config.get("base_url") + "file/report"
        params = dict(
            apikey=api_key or self.api_key,
            resource=request.sha256,
        )

        json_response = None
        try:
            r = requests.get(url, params=params)
            r.raise_for_status()

            if r.ok:
                json_response = r.json()
            elif r.status_code == 204:
                message = "You exceeded the public API request rate limit (4 requests of any nature per minute)"
                raise VTException(message)
        except requests.ConnectionError:
            self.log.exception(f"ConnectionError: Couldn't connect to: {url}")
        except requests.HTTPError as e:
            self.log.exception(str(e))
            raise
        except requests.exceptions.RequestException as e:  # All other types of exceptions
            self.log.exception(str(e))
            raise
        except:
            raise

        return json_response

    def parse_results(self, response: Dict[str, Any]):
        res = Result()
        response = response.get('results', response)

        if response is not None and response.get('response_code') == 1:
            url_section = ResultSection('Virus total report permalink',
                                        body_format=BODY_FORMAT.URL,
                                        body=json.dumps({"url": response.get('permalink')}))
            res.add_section(url_section)

            scans = response.get('scans', response)
            av_hits = ResultSection('Anti-Virus Detections')
            av_hits.add_line(f'Found {response.get("positives")} AV hit(s) from {response.get("total")} scans.')
            for majorkey, subdict in sorted(scans.items()):
                if subdict['detected']:
                    virus_name = subdict['result']
                    av_hit_section = AvHitSection(majorkey, virus_name)
                    av_hit_section.set_heuristic(1, signature=f'{majorkey}.{virus_name}')
                    av_hit_section.add_tag('av.virus_name', virus_name)
                    av_hits.add_subsection(av_hit_section)

            res.add_section(av_hits)

        return res
