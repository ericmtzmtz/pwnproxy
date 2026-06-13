import logging
from typing import Optional

import httpx

from pwnproxy.shared.scan.params import InjectionPoint
from pwnproxy.plugins.scanners.xxe.mutator import XML_CONTENT_TYPES, build_xml_with_entity, json_to_xml

logger = logging.getLogger(__name__)


class XxeReplayer:
    def __init__(self):
        self._client = httpx.AsyncClient(verify=False, follow_redirects=False)

    async def replay_xml(
        self,
        point: InjectionPoint,
        xml_body: str,
    ) -> Optional[httpx.Response]:
        headers = dict(point.original_headers)
        headers["content-type"] = "application/xml"
        headers.pop("content-length", None)

        try:
            resp = await self._client.request(
                point.method,
                point.url,
                headers=headers,
                content=xml_body.encode(),
                timeout=5.0,
            )
            return resp
        except httpx.TimeoutException:
            logger.debug(f"Timeout for XXE on {point.url}")
            return None
        except Exception as e:
            logger.warning(f"XXE replay failed for {point.url}: {e}")
            return None

    async def replay_json_mutated(
        self,
        point: InjectionPoint,
        entity_decl: str,
        entity_ref: str = "&xxe;",
    ) -> Optional[httpx.Response]:
        if not point.original_body:
            return None
        xml_body = build_xml_with_entity(point.original_body, entity_decl, entity_ref)
        if xml_body is None:
            return None
        return await self.replay_xml(point, xml_body)

    async def replay_raw_body(
        self,
        point: InjectionPoint,
        body: str,
        content_type: str = "application/xml",
    ) -> Optional[httpx.Response]:
        headers = dict(point.original_headers)
        headers["content-type"] = content_type
        headers.pop("content-length", None)

        try:
            resp = await self._client.request(
                point.method,
                point.url,
                headers=headers,
                content=body.encode(),
                timeout=5.0,
            )
            return resp
        except httpx.TimeoutException:
            logger.debug(f"Timeout for raw body XXE on {point.url}")
            return None
        except Exception as e:
            logger.warning(f"Raw body XXE replay failed for {point.url}: {e}")
            return None

    async def close(self) -> None:
        await self._client.aclose()
