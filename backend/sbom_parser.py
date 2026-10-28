"""
Module 1: SBOM Parser (Enhanced)
Parses Software Bill of Materials and also auto-generates SBOM from:
  - CycloneDX JSON (bomFormat: CycloneDX)
  - SPDX JSON
  - Simple JSON {"dependencies": {...}}
  - requirements.txt (Python pip)
  - package.json / package-lock.json (Node.js npm)
  - pom.xml (Java Maven) — basic parser
  - Pipfile / Pipfile.lock
  - go.sum / go.mod (Go modules) — basic parser
"""
import json
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Any


class SBOMParser:
    """
    Module 1: SBOM Parser
    Parses Software Bill of Materials (JSON / CycloneDX / SPDX format)
    and extracts normalized components and versions.
    Supports auto-SBOM generation from dependency files.
    """

    @staticmethod
    def parse_sbom_data(sbom_content: Any) -> List[Dict[str, Any]]:
        """
        Parses raw dict or JSON string representing an SBOM file.
        Returns a clean list of component dictionaries.
        """
        if isinstance(sbom_content, str):
            try:
                sbom_content = json.loads(sbom_content)
            except json.JSONDecodeError:
                return SBOMParser.auto_detect_and_parse("", sbom_content)

        components = []

        # 1. CycloneDX Format
        if "components" in sbom_content:
            for item in sbom_content["components"]:
                comp_name = item.get("name", "").strip().lower()
                if comp_name:
                    components.append({
                        "name": comp_name,
                        "version": item.get("version", "unknown"),
                        "purl": item.get("purl", f"pkg:generic/{comp_name}@{item.get('version', '0.0')}"),
                        "type": item.get("type", "library"),
                        "is_direct": item.get("isDirectDependency", True)
                    })

        # 2. SPDX Format
        elif "packages" in sbom_content:
            for item in sbom_content["packages"]:
                comp_name = item.get("name", "").strip().lower()
                if comp_name:
                    components.append({
                        "name": comp_name,
                        "version": item.get("versionInfo", item.get("version", "unknown")),
                        "purl": item.get("downloadLocation", f"pkg:generic/{comp_name}"),
                        "type": "library",
                        "is_direct": True
                    })

        # 3. Simple JSON key-value fallback (e.g. {"dependencies": {"django": "2.2.0"}})
        elif "dependencies" in sbom_content:
            deps = sbom_content["dependencies"]
            if isinstance(deps, dict):
                for comp_name, ver in deps.items():
                    if isinstance(ver, str):
                        clean_ver = ver.lstrip("^~>=<").split(" ")[0]
                    else:
                        clean_ver = str(ver)
                    components.append({
                        "name": comp_name.strip().lower(),
                        "version": clean_ver,
                        "purl": f"pkg:npm/{comp_name}@{clean_ver}",
                        "type": "library",
                        "is_direct": True
                    })

        return components

    @staticmethod
    def parse_requirements_txt(content: str) -> List[Dict[str, Any]]:
        """
        Auto-generate SBOM from Python requirements.txt file content.
        Handles: django==3.2.0, requests>=2.20, flask~=1.1.2, -r other.txt, #comments
        """
        components = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-") or line.startswith("git+"):
                continue
            # Parse package==version, package>=version, package~=version, package[extras]==version
            match = re.match(r"^([A-Za-z0-9_\-\.]+)(?:\[.*?\])?(?:[><=~!]+([A-Za-z0-9_\.\-]+))?", line)
            if match:
                name = match.group(1).strip().lower()
                version = match.group(2).strip() if match.group(2) else "unknown"
                if name:
                    components.append({
                        "name": name,
                        "version": version,
                        "purl": f"pkg:pypi/{name}@{version}",
                        "type": "library",
                        "is_direct": True
                    })
        return components

    @staticmethod
    def parse_package_json(content: str) -> List[Dict[str, Any]]:
        """
        Auto-generate SBOM from Node.js package.json content.
        Parses both 'dependencies' and 'devDependencies'.
        """
        components = []
        try:
            pkg = json.loads(content)
        except json.JSONDecodeError:
            return components

        for dep_type, is_direct in [("dependencies", True), ("devDependencies", False)]:
            for name, ver_spec in pkg.get(dep_type, {}).items():
                clean_ver = str(ver_spec).lstrip("^~>=<").split(" ")[0]
                components.append({
                    "name": name.strip().lower(),
                    "version": clean_ver,
                    "purl": f"pkg:npm/{name}@{clean_ver}",
                    "type": "library",
                    "is_direct": is_direct
                })
        return components

    @staticmethod
    def parse_package_lock_json(content: str) -> List[Dict[str, Any]]:
        """
        Parse package-lock.json for exact resolved versions (more precise than package.json).
        """
        components = []
        try:
            lock = json.loads(content)
        except json.JSONDecodeError:
            return components

        # npm lockfile v2/v3 format
        packages = lock.get("packages", {})
        for pkg_path, meta in packages.items():
            if not pkg_path or pkg_path == "":
                continue  # skip root entry
            name = pkg_path.replace("node_modules/", "").strip().lower()
            version = meta.get("version", "unknown")
            dev = meta.get("dev", False)
            components.append({
                "name": name,
                "version": version,
                "purl": f"pkg:npm/{name}@{version}",
                "type": "library",
                "is_direct": not dev
            })

        # npm lockfile v1 format (dependencies key)
        if not packages and "dependencies" in lock:
            for name, meta in lock["dependencies"].items():
                version = meta.get("version", "unknown")
                components.append({
                    "name": name.strip().lower(),
                    "version": version,
                    "purl": f"pkg:npm/{name}@{version}",
                    "type": "library",
                    "is_direct": True
                })
        return components

    @staticmethod
    def parse_pom_xml(content: str) -> List[Dict[str, Any]]:
        """
        Auto-generate SBOM from Maven pom.xml dependency declarations.
        Parses <dependency> blocks inside <dependencies>.
        """
        components = []
        try:
            # Strip XML namespaces for simpler parsing
            content_clean = re.sub(r'xmlns[^"]*"[^"]*"', '', content)
            content_clean = re.sub(r'\s+', ' ', content_clean)
            root = ET.fromstring(content_clean)

            def find_deps(node):
                deps_node = node.find(".//dependencies")
                if deps_node is None:
                    return []
                result = []
                for dep in deps_node.findall("dependency"):
                    group_id = (dep.findtext("groupId") or "").strip()
                    artifact_id = (dep.findtext("artifactId") or "").strip()
                    version = (dep.findtext("version") or "unknown").strip()
                    scope = (dep.findtext("scope") or "compile").strip()
                    if artifact_id:
                        name = artifact_id.lower()
                        result.append({
                            "name": name,
                            "version": version.lstrip("${").rstrip("}"),
                            "purl": f"pkg:maven/{group_id}/{artifact_id}@{version}",
                            "type": "library",
                            "is_direct": scope not in ["test", "provided"]
                        })
                return result

            components = find_deps(root)
        except ET.ParseError:
            pass
        return components

    @staticmethod
    def parse_go_mod(content: str) -> List[Dict[str, Any]]:
        """
        Auto-generate SBOM from Go go.mod file.
        Parses 'require' blocks.
        """
        components = []
        in_require_block = False
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("require ("):
                in_require_block = True
                continue
            if in_require_block and line == ")":
                in_require_block = False
                continue
            if in_require_block or line.startswith("require "):
                clean = line.replace("require ", "").strip()
                parts = clean.split()
                if len(parts) >= 2 and not parts[0].startswith("//"):
                    name = parts[0].lower()
                    version = parts[1].lstrip("v")
                    components.append({
                        "name": name.split("/")[-1],  # last path segment as name
                        "version": version,
                        "purl": f"pkg:golang/{name}@v{version}",
                        "type": "library",
                        "is_direct": True
                    })
        return components

    @classmethod
    def parse_csv_components(cls, content: str) -> List[Dict[str, Any]]:
        """Parse CSV or TSV list of components."""
        import csv
        import io
        components = []
        try:
            first_line = content.splitlines()[0] if content.splitlines() else ""
            delim = "\t" if "\t" in first_line else (";" if ";" in first_line and "," not in first_line else ",")
            reader = csv.DictReader(io.StringIO(content), delimiter=delim)
            for row in reader:
                name = ""
                version = "unknown"
                for k, v in row.items():
                    kl = str(k).strip().lower()
                    if kl in ["name", "component", "package", "library"]:
                        name = str(v).strip().lower()
                    elif kl in ["version", "ver", "installed"]:
                        version = str(v).strip()
                if name:
                    components.append({
                        "name": name,
                        "version": version,
                        "purl": f"pkg:generic/{name}@{version}",
                        "type": "library",
                        "is_direct": True
                    })
        except Exception:
            pass
        return components

    @classmethod
    def auto_detect_and_parse(cls, filename: str, content: str) -> List[Dict[str, Any]]:
        """
        Auto-detect file type from filename or content inspection and parse accordingly.
        Supports: requirements.txt, package.json, package-lock.json, pom.xml, go.mod, CSV, JSON SBOM.
        """
        fname = filename.lower().strip()
        c_strip = content.strip() if isinstance(content, str) else ""

        if fname == "requirements.txt" or fname.endswith("/requirements.txt") or fname.endswith("\\requirements.txt"):
            return cls.parse_requirements_txt(content)
        elif fname == "package-lock.json":
            return cls.parse_package_lock_json(content)
        elif fname == "package.json":
            return cls.parse_package_json(content)
        elif fname.endswith(".xml") or "<project" in c_strip or "<dependencies" in c_strip:
            return cls.parse_pom_xml(content)
        elif fname in ("go.mod", "go.sum") or c_strip.startswith("module ") or "require (" in c_strip:
            return cls.parse_go_mod(content)
        elif fname.endswith((".csv", ".tsv")):
            return cls.parse_csv_components(content)
        else:
            # 1. Try JSON
            if c_strip.startswith("{") or c_strip.startswith("["):
                try:
                    data = json.loads(content)
                    return cls.parse_sbom_data(data)
                except Exception:
                    pass

            # 2. Try XML
            if c_strip.startswith("<"):
                res = cls.parse_pom_xml(content)
                if res:
                    return res

            # 3. Try requirements.txt format (e.g. lines with == or >=)
            if re.search(r"^[A-Za-z0-9_\-\.]+([=><~]+|\s|$)", c_strip, re.MULTILINE):
                res = cls.parse_requirements_txt(content)
                if res:
                    return res

            # 4. Try CSV
            if "," in c_strip or "\t" in c_strip:
                res = cls.parse_csv_components(content)
                if res:
                    return res

            return []
