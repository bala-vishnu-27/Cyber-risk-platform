"""
Generates realistic 500-vulnerability reference database and large SBOM dataset for testing and enterprise demo runs.
- SBOM contains 25 realistic enterprise dependencies.
- 500-CVE Vulnerability Database contains 500 CVEs across 100+ enterprise packages.
- Running matcher produces ~24 matched vulnerabilities (with realistic Critical, High, Medium, Low severity distribution).
"""
import json
import os
import random

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 25 Target components used in the application SBOM
TARGET_COMPONENTS = [
    {"name": "log4j-core", "version": "2.14.1", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "type": "library"},
    {"name": "django", "version": "2.2.0", "purl": "pkg:pypi/django@2.2.0", "type": "framework"},
    {"name": "pyyaml", "version": "5.3.1", "purl": "pkg:pypi/pyyaml@5.3.1", "type": "library"},
    {"name": "requests", "version": "2.20.0", "purl": "pkg:pypi/requests@2.20.0", "type": "library"},
    {"name": "pillow", "version": "8.1.0", "purl": "pkg:pypi/pillow@8.1.0", "type": "library"},
    {"name": "flask", "version": "1.0.2", "purl": "pkg:pypi/flask@1.0.2", "type": "framework"},
    {"name": "spring-framework", "version": "5.3.0", "purl": "pkg:maven/org.springframework/spring-web@5.3.0", "type": "framework"},
    {"name": "jackson-databind", "version": "2.9.8", "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8", "type": "library"},
    {"name": "openssl", "version": "1.1.1k", "purl": "pkg:generic/openssl@1.1.1k", "type": "system"},
    {"name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15", "type": "library"},
    {"name": "express", "version": "4.16.4", "purl": "pkg:npm/express@4.16.4", "type": "framework"},
    {"name": "axios", "version": "0.21.0", "purl": "pkg:npm/axios@0.21.0", "type": "library"},
    {"name": "react", "version": "17.0.1", "purl": "pkg:npm/react@17.0.1", "type": "framework"},
    {"name": "numpy", "version": "1.19.0", "purl": "pkg:pypi/numpy@1.19.0", "type": "library"},
    {"name": "scipy", "version": "1.5.0", "purl": "pkg:pypi/scipy@1.5.0", "type": "library"},
    {"name": "urllib3", "version": "1.26.4", "purl": "pkg:pypi/urllib3@1.26.4", "type": "library"},
    {"name": "fastapi", "version": "0.65.0", "purl": "pkg:pypi/fastapi@0.65.0", "type": "framework"},
    {"name": "gunicorn", "version": "20.0.4", "purl": "pkg:pypi/gunicorn@20.0.4", "type": "server"},
    {"name": "cryptography", "version": "3.3.1", "purl": "pkg:pypi/cryptography@3.3.1", "type": "library"},
    {"name": "celery", "version": "5.0.5", "purl": "pkg:pypi/celery@5.0.5", "type": "library"},
    {"name": "redis", "version": "3.5.3", "purl": "pkg:pypi/redis@3.5.3", "type": "database"},
    {"name": "psycopg2", "version": "2.8.6", "purl": "pkg:pypi/psycopg2@2.8.6", "type": "database"},
    {"name": "commons-collections", "version": "3.2.1", "purl": "pkg:maven/commons-collections/commons-collections@3.2.1", "type": "library"},
    {"name": "struts2", "version": "2.5.20", "purl": "pkg:maven/org.apache.struts/struts2-core@2.5.20", "type": "framework"},
    {"name": "netty", "version": "4.1.42", "purl": "pkg:maven/io.netty/netty-all@4.1.42", "type": "library"}
]

# 80+ External enterprise packages NOT in application SBOM (or non-matching versions)
EXTERNAL_PACKAGES = [
    "tomcat", "nginx", "kernel", "node", "ruby-rack", "golang-crypto", "zlib", "sqlite3",
    "commons-fileupload", "bouncycastle", "docker-engine", "kubernetes", "istio", "envoy",
    "prometheus", "grafana", "elasticsearch", "kibana", "apache-kafka", "rabbitmq",
    "haproxy", "memcached", "mongodb-driver", "mysql-connector", "mariadb-client",
    "php-core", "systemd", "grpc-core", "protobuf", "libcurl", "gnutls", "pam", "sudo",
    "bash", "glibc", "python-core", "ruby-core", "perl-core", "open-jdk", "v8-engine",
    "webkit", "pcre", "libxml2", "libxslt", "bzip2", "xz-utils", "tar", "gzip", "rsync",
    "openssh", "bind9", "dhcpd", "snmpd", "openldap", "cyrus-sasl", "krb5", "samba",
    "freeradius", "squid", "varnish", "civetweb", "lighttpd", "cherokee", "jetty",
    "glassfish", "wildfly", "subversion", "git-core", "mercurial", "cvs", "ant", "gradle",
    "jenkins-core", "sonarqube", "gitlab-runner", "artifactory", "nexus-server", "vault",
    "consul", "etcd", "terraform", "ansible", "puppet-agent", "chef-workstation"
]

VULN_TEMPLATES = [
    {"type": "Remote Code Execution", "severity": "CRITICAL", "cvss": [9.0, 10.0], "exploit": True},
    {"type": "SQL Injection", "severity": "CRITICAL", "cvss": [9.0, 9.8], "exploit": True},
    {"type": "Deserialization of Untrusted Data", "severity": "CRITICAL", "cvss": [8.8, 9.8], "exploit": True},
    {"type": "Path Traversal", "severity": "HIGH", "cvss": [7.0, 8.5], "exploit": True},
    {"type": "Server-Side Request Forgery (SSRF)", "severity": "HIGH", "cvss": [7.2, 8.6], "exploit": False},
    {"type": "Cross-Site Scripting (XSS)", "severity": "MEDIUM", "cvss": [5.4, 6.5], "exploit": False},
    {"type": "Denial of Service (DoS)", "severity": "MEDIUM", "cvss": [5.0, 6.8], "exploit": False},
    {"type": "Information Disclosure", "severity": "LOW", "cvss": [3.0, 4.5], "exploit": False},
    {"type": "Improper Access Control", "severity": "HIGH", "cvss": [7.5, 8.8], "exploit": True},
    {"type": "Buffer Overflow", "severity": "CRITICAL", "cvss": [9.0, 9.8], "exploit": True}
]

def generate_sbom():
    components = []
    for comp in TARGET_COMPONENTS:
        components.append({
            "name": comp["name"],
            "version": comp["version"],
            "purl": comp["purl"],
            "type": comp["type"],
            "isDirectDependency": random.choice([True, False])
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": components
    }

def generate_vulnerabilities(count=500):
    vulns = []
    
    # 24 Specific Matched CVEs for application's SBOM components
    matched_cves = [
        # CRITICAL (4)
        {
            "cveId": "CVE-2021-44228", "component": "log4j-core", "affectedVersion": "2.14.1", "fixedVersion": "2.17.1",
            "cvssScore": 10.0, "severity": "CRITICAL", "exploitAvailable": True,
            "description": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell).", "publishedDate": "2021-12-10"
        },
        {
            "cveId": "CVE-2022-22965", "component": "spring-framework", "affectedVersion": "5.3.0", "fixedVersion": "5.3.18",
            "cvssScore": 9.8, "severity": "CRITICAL", "exploitAvailable": True,
            "description": "Spring Framework RCE via Data Binder parameter binding (Spring4Shell).", "publishedDate": "2022-03-31"
        },
        {
            "cveId": "CVE-2020-7471", "component": "django", "affectedVersion": "2.2.0", "fixedVersion": "2.2.10",
            "cvssScore": 9.8, "severity": "CRITICAL", "exploitAvailable": True,
            "description": "Django SQL Injection via StringAgg aggregation function.", "publishedDate": "2020-02-03"
        },
        {
            "cveId": "CVE-2021-3711", "component": "openssl", "affectedVersion": "1.1.1k", "fixedVersion": "1.1.1l",
            "cvssScore": 9.8, "severity": "CRITICAL", "exploitAvailable": True,
            "description": "SM2 Decryption Buffer Overflow vulnerability in OpenSSL.", "publishedDate": "2021-08-24"
        },

        # HIGH (7)
        {
            "cveId": "CVE-2020-14343", "component": "pyyaml", "affectedVersion": "5.3.1", "fixedVersion": "5.4",
            "cvssScore": 8.8, "severity": "HIGH", "exploitAvailable": True,
            "description": "Unsafe YAML deserialization vulnerability in PyYAML FullLoader.", "publishedDate": "2020-07-27"
        },
        {
            "cveId": "CVE-2018-18074", "component": "requests", "affectedVersion": "2.20.0", "fixedVersion": "2.20.1",
            "cvssScore": 7.5, "severity": "HIGH", "exploitAvailable": True,
            "description": "HTTP Authorization header leak on HTTPS to HTTP redirects in Requests.", "publishedDate": "2018-10-09"
        },
        {
            "cveId": "CVE-2021-25292", "component": "pillow", "affectedVersion": "8.1.0", "fixedVersion": "8.1.1",
            "cvssScore": 7.5, "severity": "HIGH", "exploitAvailable": True,
            "description": "Out-of-bounds read in Pillow TIFF decoder.", "publishedDate": "2021-03-05"
        },
        {
            "cveId": "CVE-2019-12384", "component": "jackson-databind", "affectedVersion": "2.9.8", "fixedVersion": "2.9.9.1",
            "cvssScore": 8.1, "severity": "HIGH", "exploitAvailable": True,
            "description": "Jackson-databind polymorphic deserialization gadget flaw.", "publishedDate": "2019-06-24"
        },
        {
            "cveId": "CVE-2020-17530", "component": "struts2", "affectedVersion": "2.5.20", "fixedVersion": "2.5.26",
            "cvssScore": 8.5, "severity": "HIGH", "exploitAvailable": True,
            "description": "Apache Struts2 OGNL evaluation RCE via forced tag attributes.", "publishedDate": "2020-12-08"
        },
        {
            "cveId": "CVE-2021-21290", "component": "netty", "affectedVersion": "4.1.42", "fixedVersion": "4.1.59",
            "cvssScore": 7.7, "severity": "HIGH", "exploitAvailable": False,
            "description": "Netty temporary file disclosure vulnerability on Unix systems.", "publishedDate": "2021-02-08"
        },
        {
            "cveId": "CVE-2021-23337", "component": "lodash", "affectedVersion": "4.17.15", "fixedVersion": "4.17.21",
            "cvssScore": 7.2, "severity": "HIGH", "exploitAvailable": False,
            "description": "Command Injection via template function in Lodash.", "publishedDate": "2021-02-15"
        },

        # MEDIUM (9)
        {
            "cveId": "CVE-2019-1010083", "component": "flask", "affectedVersion": "1.0.2", "fixedVersion": "1.0.3",
            "cvssScore": 5.3, "severity": "MEDIUM", "exploitAvailable": False,
            "description": "Session cookie handling vulnerability across subdomains in Flask.", "publishedDate": "2019-07-17"
        },
        {
            "cveId": "CVE-2020-7662", "component": "express", "affectedVersion": "4.16.4", "fixedVersion": "4.17.1",
            "cvssScore": 6.1, "severity": "MEDIUM", "exploitAvailable": False,
            "description": "Open redirect vulnerability in Express query parser.", "publishedDate": "2020-06-11"
        },
        {
            "cveId": "CVE-2020-28168", "component": "axios", "affectedVersion": "0.21.0", "fixedVersion": "0.21.1",
            "cvssScore": 5.9, "severity": "MEDIUM", "exploitAvailable": False,
            "description": "Axios SSRF vulnerability via bypass of proxy settings.", "publishedDate": "2020-11-11"
        },
        {
            "cveId": "CVE-2021-24031", "component": "react", "affectedVersion": "17.0.1", "fixedVersion": "17.0.2",
            "cvssScore": 5.4, "severity": "MEDIUM", "exploitAvailable": False,
            "description": "Reflected XSS in React server-side rendering component.", "publishedDate": "2021-04-12"
        },
        {
            "cveId": "CVE-2021-33574", "component": "numpy", "affectedVersion": "1.19.0", "fixedVersion": "1.21.0",
            "cvssScore": 6.5, "severity": "MEDIUM", "exploitAvailable": False,
            "description": "Buffer overflow in NumPy string formatting routine.", "publishedDate": "2021-05-24"
        },
        {
            "cveId": "CVE-2021-33430", "component": "cryptography", "affectedVersion": "3.3.1", "fixedVersion": "3.4.7",
            "cvssScore": 5.5, "severity": "MEDIUM", "exploitAvailable": False,
            "description": "Memory corruption flaw in PyOpenSSL cryptography bindings.", "publishedDate": "2021-05-18"
        },
        {
            "cveId": "CVE-2021-31542", "component": "celery", "affectedVersion": "5.0.5", "fixedVersion": "5.1.0",
            "cvssScore": 6.3, "severity": "MEDIUM", "exploitAvailable": False,
            "description": "Unchecked redis backend protocol deserialization in Celery.", "publishedDate": "2021-04-28"
        },
        {
            "cveId": "CVE-2021-32715", "component": "redis", "affectedVersion": "3.5.3", "fixedVersion": "4.0.0",
            "cvssScore": 5.3, "severity": "MEDIUM", "exploitAvailable": False,
            "description": "Integer overflow in Redis command buffer parser.", "publishedDate": "2021-07-21"
        },
        {
            "cveId": "CVE-2021-32630", "component": "psycopg2", "affectedVersion": "2.8.6", "fixedVersion": "2.9.1",
            "cvssScore": 5.8, "severity": "MEDIUM", "exploitAvailable": False,
            "description": "Connection string escaping issue in psycopg2 driver.", "publishedDate": "2021-06-15"
        },

        # LOW (4)
        {
            "cveId": "CVE-2021-33431", "component": "scipy", "affectedVersion": "1.5.0", "fixedVersion": "1.6.0",
            "cvssScore": 3.8, "severity": "LOW", "exploitAvailable": False,
            "description": "Null pointer dereference in SciPy BLAS wrapper.", "publishedDate": "2021-05-19"
        },
        {
            "cveId": "CVE-2021-33503", "component": "urllib3", "affectedVersion": "1.26.4", "fixedVersion": "1.26.5",
            "cvssScore": 3.4, "severity": "LOW", "exploitAvailable": False,
            "description": "CRLF injection via HTTP request header in urllib3.", "publishedDate": "2021-06-02"
        },
        {
            "cveId": "CVE-2021-32677", "component": "fastapi", "affectedVersion": "0.65.0", "fixedVersion": "0.68.0",
            "cvssScore": 3.7, "severity": "LOW", "exploitAvailable": False,
            "description": "ReDoS vulnerability in FastAPI OpenAPI schema parser.", "publishedDate": "2021-08-09"
        },
        {
            "cveId": "CVE-2021-32839", "component": "gunicorn", "affectedVersion": "20.0.4", "fixedVersion": "20.1.0",
            "cvssScore": 3.3, "severity": "LOW", "exploitAvailable": False,
            "description": "HTTP request smuggling via malformed Transfer-Encoding header in Gunicorn.", "publishedDate": "2021-08-16"
        }
    ]
    
    vulns.extend(matched_cves)
    
    # Generate remaining ~476 CVEs for external packages NOT in application's SBOM
    year_weights = [2020, 2021, 2022, 2023, 2024, 2025]
    for i in range(len(matched_cves) + 1, count + 1):
        pkg = random.choice(EXTERNAL_PACKAGES)
        tmpl = random.choice(VULN_TEMPLATES)
        year = random.choice(year_weights)
        cve_num = random.randint(1000, 99999)
        cve_id = f"CVE-{year}-{cve_num}"
        cvss = round(random.uniform(tmpl["cvss"][0], tmpl["cvss"][1]), 1)
        ver_major = random.randint(1, 9)
        ver_minor = random.randint(0, 15)
        
        vulns.append({
            "cveId": cve_id,
            "component": pkg,
            "affectedVersion": f"{ver_major}.{ver_minor}.0",
            "fixedVersion": f"{ver_major}.{ver_minor}.1",
            "cvssScore": cvss,
            "severity": tmpl["severity"],
            "exploitAvailable": tmpl["exploit"],
            "description": f"{tmpl['type']} security vulnerability identified in enterprise package {pkg} version {ver_major}.{ver_minor}.0.",
            "publishedDate": f"{year}-{random.randint(1,12):02d}-{random.randint(1,28):02d}"
        })
        
    return {"vulnerabilities": vulns}

if __name__ == "__main__":
    random.seed(42)  # Consistent generation for reproducibility
    sbom_data = generate_sbom()
    vuln_data = generate_vulnerabilities(500)
    
    sbom_file = os.path.join(BASE_DIR, "real_sbom_large.json")
    vuln_file = os.path.join(BASE_DIR, "real_vulnerabilities_500.json")
    
    with open(sbom_file, "w", encoding="utf-8") as f:
        json.dump(sbom_data, f, indent=2)
        
    with open(vuln_file, "w", encoding="utf-8") as f:
        json.dump(vuln_data, f, indent=2)
        
    print(f"[SUCCESS] Generated {len(sbom_data['components'])} SBOM components -> {sbom_file}")
    print(f"[SUCCESS] Generated {len(vuln_data['vulnerabilities'])} Reference Vulnerability records -> {vuln_file}")

