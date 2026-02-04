#!/usr/bin/env python3
from __future__ import annotations

import csv
import os
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

import networkx as nx


MITRE_TAG_RE = re.compile(r"attack\.(t\d{4})(?:\.(\d{3}))?", re.IGNORECASE)

# Curated subset from Knowledge-enhanced-Attack-Graph (fallback when GML not provided)
PICKED_TECHNIQUES_NAME_DICT = {
    "/techniques/T1566/001": "Phishing",
    "/techniques/T1566/002": "Phishing",
    "/techniques/T1566/003": "Phishing",
    "/techniques/T1195/001": "Supply Chain Compromise",
    "/techniques/T1195/002": "Supply Chain Compromise",
    "/techniques/T1059/001": "Command and Scripting Interpreter",
    "/techniques/T1059/003": "Command and Scripting Interpreter",
    "/techniques/T1059/005": "Command and Scripting Interpreter",
    "/techniques/T1059/007": "Command and Scripting Interpreter",
    "/techniques/T1559/001": "Inter-Process Communication",
    "/techniques/T1204/001": "User Execution: Malicious Link",
    "/techniques/T1204/002": "User Execution: Malicious File",
    "/techniques/T1053/005": "Scheduled Task/Job",
    "/techniques/T1037/001": "Boot or Logon Initialization Scripts",
    "/techniques/T1547/001": "Boot or Logon Autostart Execution",
    "/techniques/T1547/002": "Boot or Logon Autostart Execution",
    "/techniques/T1112": "Modify Registry",
    "/techniques/T1012": "Query Registry",
    "/techniques/T1218/005": "Signed Binary Proxy Execution: Mshta",
    "/techniques/T1218/010": "Signed Binary Proxy Execution: REgsvr32",
    "/techniques/T1218/011": "Signed Binary Proxy Execution: Rundll32",
    "/techniques/T1078/001": "Valid Accounts",
    "/techniques/T1518/001": "Software Discovery",
    "/techniques/T1083": "File and Directory Discovery",
    "/techniques/T1057": "Process Discovery",
    "/techniques/T1497/001": "Virtualization/Sandbox Evasion",
    "/techniques/T1560/001": "Archive Collected Data",
    "/techniques/T1123": "Audio Capture",
    "/techniques/T1119": "Automated Collection",
    "/techniques/T1041": "Exfiltration Over C2 Channel",
}


def parse_attack_tag(tag: str) -> Optional[Tuple[str, Optional[str]]]:
    match = MITRE_TAG_RE.match(tag.strip()) if isinstance(tag, str) else None
    if not match:
        return None
    return match.group(1).upper(), match.group(2)


def tag_to_mitre_node_id(tag: str) -> Optional[str]:
    parsed = parse_attack_tag(tag)
    if not parsed:
        return None
    base, sub = parsed
    if sub:
        return f"/techniques/{base}/{sub}"
    return f"/techniques/{base}"


@dataclass
class TechniqueInfo:
    node_id: str
    technique_id: str
    name: str
    tactic: Optional[str]
    tactic_name: Optional[str]


def _read_csv_as_dict(csv_file: str) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    with open(csv_file, newline="", encoding="utf-8") as csv_stream:
        csv_reader = csv.reader(csv_stream)
        for row in csv_reader:
            if len(row) < 2:
                continue
            mapping[row[1]] = row[0]
    return mapping


class MitreGraphReader:
    def __init__(self, gml_location: str, link_file_map_file: Optional[str] = None):
        self.mitre_graph = nx.read_gml(gml_location)
        self.link_file_map = _read_csv_as_dict(link_file_map_file) if link_file_map_file else {}

    def get_super_for_technique(self, technique_id: str) -> str:
        if self.mitre_graph.nodes[technique_id].get("types") != "sub_technique":
            return technique_id
        for n in self.mitre_graph.neighbors(technique_id):
            if self.mitre_graph.nodes[n].get("types") == "super_technique":
                return n
        return technique_id

    def get_name_for_technique(self, technique_id: str) -> Optional[str]:
        node = self.mitre_graph.nodes.get(technique_id)
        return node.get("name") if node else None

    def get_tactic_for_technique(self, technique_id: str) -> Optional[str]:
        if self.mitre_graph.nodes[technique_id].get("types") == "sub_technique":
            technique_id = self.get_super_for_technique(technique_id)
        for n in self.mitre_graph.neighbors(technique_id):
            if self.mitre_graph.nodes[n].get("types") == "tactic":
                return n
        return None

    def get_name_for_tactic(self, tactic_id: str) -> Optional[str]:
        node = self.mitre_graph.nodes.get(tactic_id)
        return node.get("name") if node else None


class TTPMapper:
    def __init__(self, gml_path: Optional[str] = None, link_map_path: Optional[str] = None,
                 keag_root: Optional[str] = None):
        if gml_path is None:
            keag_root = keag_root or os.path.join("external", "Knowledge-enhanced-Attack-Graph")
            keag_gml = os.path.join(keag_root, "Tactic_Technique_Reference_Example.gml")
            keag_link = os.path.join(keag_root, "html_url_hash.csv")
            if os.path.exists(keag_gml):
                gml_path = keag_gml
                if os.path.exists(keag_link):
                    link_map_path = link_map_path or keag_link
        self.reader = MitreGraphReader(gml_path, link_map_path) if gml_path else None

    def map_tags(self, tags: Iterable[str]) -> List[TechniqueInfo]:
        out: List[TechniqueInfo] = []
        for tag in tags:
            node_id = tag_to_mitre_node_id(tag)
            if not node_id:
                continue
            technique_id = node_id.replace("/techniques/", "").replace("/", ".")
            name = None
            tactic = None
            tactic_name = None
            if self.reader:
                name = self.reader.get_name_for_technique(node_id)
                tactic = self.reader.get_tactic_for_technique(node_id)
                if tactic:
                    tactic_name = self.reader.get_name_for_tactic(tactic)
            if not name:
                name = PICKED_TECHNIQUES_NAME_DICT.get(node_id, "")
            out.append(TechniqueInfo(
                node_id=node_id,
                technique_id=technique_id,
                name=name or "",
                tactic=tactic,
                tactic_name=tactic_name,
            ))
        return out
