import ipaddress
import json
import math
import os
import random
import re
import socket
from urllib import error, request
from urllib.parse import parse_qs, urlparse

from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier, VotingClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

BRAND_OFFICIAL_DOMAINS = {
    "amazon": {"amazon.com", "amazon.in"},
    "apple": {"apple.com"},
    "bankofamerica": {"bankofamerica.com"},
    "coinbase": {"coinbase.com"},
    "dropbox": {"dropbox.com"},
    "facebook": {"facebook.com"},
    "google": {"google.com"},
    "hdfc": {"hdfcbank.com"},
    "icici": {"icicibank.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "microsoft": {"microsoft.com"},
    "netflix": {"netflix.com"},
    "nordvpn": {"nordvpn.com"},
    "openai": {"openai.com"},
    "paypal": {"paypal.com"},
    "sbi": {"onlinesbi.sbi", "sbi.co.in", "sbi"},
    "telegram": {"telegram.org"},
    "whatsapp": {"whatsapp.com"},
}

COMMON_SECOND_LEVEL_SUFFIXES = {
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "co.in",
    "org.in",
    "gov.in",
    "com.au",
    "co.nz",
    "co.jp",
}


class PhishingURLDetector:
    def __init__(self):
        self.pipeline = Pipeline(
            [
                ("vectorizer", DictVectorizer(sparse=False)),
                (
                    "classifier",
                    VotingClassifier(
                        estimators=[
                            (
                                "logistic",
                                LogisticRegression(max_iter=4000, random_state=42),
                            ),
                            (
                                "forest",
                                RandomForestClassifier(
                                    n_estimators=260,
                                    max_depth=14,
                                    min_samples_leaf=2,
                                    random_state=42,
                                ),
                            ),
                            (
                                "boosting",
                                GradientBoostingClassifier(
                                    n_estimators=180,
                                    learning_rate=0.05,
                                    max_depth=3,
                                    random_state=42,
                                ),
                            ),
                        ],
                        voting="soft",
                        weights=[2, 2, 1],
                    ),
                ),
            ]
        )
        self._fit()

    def _fit(self):
        dataset = self._build_dataset()
        features = [self._extract_features(url) for url, _ in dataset]
        labels = [label for _, label in dataset]
        self.pipeline.fit(features, labels)

    def _build_dataset(self):
        rng = random.Random(42)
        brands = [
            "paypal",
            "microsoft",
            "google",
            "amazon",
            "apple",
            "netflix",
            "bankofamerica",
            "instagram",
            "facebook",
            "dropbox",
            "icici",
            "hdfc",
            "sbi",
            "whatsapp",
            "telegram",
            "coinbase",
            "nordvpn",
        ]
        benign_domains = [
            "google.com",
            "github.com",
            "microsoft.com",
            "apple.com",
            "wikipedia.org",
            "amazon.in",
            "linkedin.com",
            "stackoverflow.com",
            "openai.com",
            "coursera.org",
            "nasa.gov",
            "python.org",
            "icicibank.com",
            "onlinesbi.sbi",
            "nordvpn.com",
        ]
        safe_paths = [
            "",
            "/about",
            "/support",
            "/pricing",
            "/blog/product-update",
            "/docs/start",
            "/account/security",
            "/learn/python",
            "/company/contact",
            "/products/cloud",
        ]
        safe_queries = [
            "",
            "?page=1",
            "?ref=homepage",
            "?category=tools",
            "?lang=en",
            "?view=overview",
        ]
        suspicious_words = [
            "login",
            "verify",
            "secure",
            "update",
            "confirm",
            "unlock",
            "billing",
            "password",
            "alert",
            "bonus",
            "gift",
            "wallet",
            "otp",
            "kyc",
            "suspended",
        ]
        risky_tlds = [".ru", ".tk", ".ml", ".gq", ".cf", ".xyz", ".top", ".click"]
        safe_tlds = [".com", ".org", ".net", ".in", ".edu"]

        dataset = []

        for domain in benign_domains:
            for path in safe_paths:
                query = rng.choice(safe_queries)
                prefix = rng.choice(["https://", "https://www.", "http://www."])
                dataset.append((f"{prefix}{domain}{path}{query}", 0))
                dataset.append((f"https://support.{domain}{path}", 0))

        for brand in brands:
            legit_hosts = [
                f"https://www.{brand}.com",
                f"https://support.{brand}.com",
                f"https://accounts.{brand}.com/security",
                f"https://login.{brand}.com",
            ]
            dataset.extend((url, 0) for url in legit_hosts)

            for word in suspicious_words:
                dataset.append(
                    (
                        f"http://{brand}-{word}-security{rng.choice(risky_tlds)}/session/check",
                        1,
                    )
                )
                dataset.append(
                    (
                        f"https://{word}-{brand}-account.com.verify-user{rng.choice(risky_tlds)}/login",
                        1,
                    )
                )
                dataset.append(
                    (
                        f"http://{rng.randint(10, 250)}.{rng.randint(1, 250)}.{rng.randint(1, 250)}.{rng.randint(1, 250)}/{brand}/{word}/",
                        1,
                    )
                )
                dataset.append(
                    (
                        f"https://secure-{brand}.com@{word}-{brand}{rng.choice(risky_tlds)}/update?token={rng.randint(10000, 99999)}",
                        1,
                    )
                )
                dataset.append(
                    (
                        f"http://{brand}.{word}.auth.user.session{rng.choice(risky_tlds)}/web/login/reset",
                        1,
                    )
                )
                dataset.append(
                    (
                        f"https://{brand}-{word}-{rng.randint(100, 999)}{rng.choice(safe_tlds)}/free/reward",
                        1,
                    )
                )

        phishing_templates = [
            "http://account-security-check.xyz/login/verify",
            "http://secure-billing-update.top/payments/confirm",
            "https://login-warning-alert.ru/webscr/index",
            "http://mail-authentication.tk/owa/login",
            "http://bonus-reward-center.cf/free-gift",
            "http://urgent-validation.ml/password/reset",
            "https://verify-session-now.gq/update/billing",
            "http://otp-check-wallet.click/security/confirm",
            "http://bank-login-verify.xyz/customer/update/kyc",
        ]
        dataset.extend((url, 1) for url in phishing_templates)

        rng.shuffle(dataset)
        return dataset

    def _prepare_url(self, raw_url):
        candidate = raw_url.strip()
        if not candidate:
            return ""
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
            return f"https://{candidate}"
        return candidate

    def _hostname_resolves(self, hostname):
        timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(2.5)
            socket.getaddrinfo(hostname, None)
            return True
        except socket.gaierror:
            return False
        except OSError:
            return False
        finally:
            socket.setdefaulttimeout(timeout)

    def _registered_domain(self, hostname):
        labels = [label for label in hostname.split(".") if label]
        if len(labels) < 2:
            return hostname

        tail_two = ".".join(labels[-2:])
        if tail_two in COMMON_SECOND_LEVEL_SUFFIXES and len(labels) >= 3:
            return ".".join(labels[-3:])
        return tail_two

    def _hostname_matches_domain(self, hostname, domain):
        return hostname == domain or hostname.endswith(f".{domain}")

    def _levenshtein_distance(self, left, right):
        if left == right:
            return 0
        if not left:
            return len(right)
        if not right:
            return len(left)

        previous_row = list(range(len(right) + 1))
        for i, left_char in enumerate(left, start=1):
            current_row = [i]
            for j, right_char in enumerate(right, start=1):
                insert_cost = current_row[j - 1] + 1
                delete_cost = previous_row[j] + 1
                replace_cost = previous_row[j - 1] + (left_char != right_char)
                current_row.append(min(insert_cost, delete_cost, replace_cost))
            previous_row = current_row
        return previous_row[-1]

    def _looks_like_brand_typo(self, candidate, brand):
        if not candidate or not brand:
            return False
        if candidate == brand:
            return False
        if abs(len(candidate) - len(brand)) > 2:
            return False

        distance = self._levenshtein_distance(candidate, brand)
        threshold = 1 if len(brand) <= 7 else 2
        return distance <= threshold

    def _brand_typo_candidates(self, hostname, registered_domain):
        candidates = set()
        for value in {hostname, registered_domain}:
            if not value:
                continue
            for label in value.split("."):
                cleaned = re.sub(r"[^a-z0-9-]", "", label.lower()).strip("-")
                if not cleaned:
                    continue
                candidates.add(cleaned)
                for part in cleaned.split("-"):
                    part = part.strip()
                    if part:
                        candidates.add(part)
        return candidates

    def _brand_domain_analysis(self, hostname):
        normalized_host = hostname.lower()
        squeezed_host = normalized_host.replace("-", "").replace(".", "")
        registered_domain = self._registered_domain(normalized_host) if normalized_host else ""
        typo_candidates = self._brand_typo_candidates(normalized_host, registered_domain)
        mentioned_brands = []
        official_brands = []
        impersonated_brands = []
        typo_brands = []

        for brand, domains in BRAND_OFFICIAL_DOMAINS.items():
            has_exact_brand = brand in normalized_host or brand in squeezed_host
            has_typo_brand = any(self._looks_like_brand_typo(candidate, brand) for candidate in typo_candidates)
            if not has_exact_brand and not has_typo_brand:
                continue

            mentioned_brands.append(brand)
            if any(self._hostname_matches_domain(normalized_host, domain) for domain in domains):
                official_brands.append(brand)
            else:
                impersonated_brands.append(brand)
                if has_typo_brand and not has_exact_brand:
                    typo_brands.append(brand)

        return {
            "mentioned_brands": mentioned_brands,
            "official_brands": official_brands,
            "impersonated_brands": impersonated_brands,
            "typo_brands": typo_brands,
            "registered_domain": registered_domain,
        }

    def _validate_url(self, raw_url):
        issues = []
        normalized = self._prepare_url(raw_url)

        if not raw_url.strip():
            issues.append("Enter a URL to analyze.")
            return {
                "valid": False,
                "issues": issues,
                "normalized_url": normalized,
                "hostname": "",
                "scheme": "",
                "uses_ip": False,
            }

        if re.search(r"\s", raw_url):
            issues.append("Spaces are not allowed inside a URL.")

        parsed = urlparse(normalized)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            issues.append("Only http:// and https:// links are supported.")

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            issues.append("The URL needs a domain name like example.com.")

        uses_ip = False
        if hostname:
            if len(hostname) > 253:
                issues.append("The domain name is too long.")
            if ".." in hostname:
                issues.append("The domain contains consecutive dots.")

            try:
                uses_ip = True
                ipaddress.ip_address(hostname.strip("[]"))
            except ValueError:
                uses_ip = False

            if not uses_ip:
                if "." not in hostname:
                    issues.append("The domain should include a top-level domain like .com.")

                label_pattern = re.compile(r"^[a-z0-9-]{1,63}$")
                labels = hostname.split(".")
                for label in labels:
                    if not label:
                        issues.append("The domain contains an empty label.")
                        break
                    if label.startswith("-") or label.endswith("-"):
                        issues.append("Domain labels cannot start or end with a hyphen.")
                        break
                    if "_" in label:
                        issues.append("Underscores are not allowed in domain names.")
                        break
                    if not (label_pattern.fullmatch(label) or label.startswith("xn--")):
                        issues.append("The domain contains invalid characters.")
                        break

                if labels:
                    tld = labels[-1]
                    if not (re.fullmatch(r"[a-z]{2,24}", tld) or tld.startswith("xn--")):
                        issues.append("The top-level domain looks invalid.")

                if not issues and not self._hostname_resolves(hostname):
                    issues.append("The domain does not appear to exist.")

        try:
            port = parsed.port
            if port is not None and not (1 <= port <= 65535):
                issues.append("The port number is out of range.")
        except ValueError:
            issues.append("The port number is invalid.")

        return {
            "valid": not issues,
            "issues": issues,
            "normalized_url": normalized,
            "hostname": hostname,
            "scheme": scheme,
            "uses_ip": uses_ip,
        }

    def _shannon_entropy(self, text):
        if not text:
            return 0.0
        counts = {}
        for char in text:
            counts[char] = counts.get(char, 0) + 1
        entropy = 0.0
        length = len(text)
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return round(entropy, 4)

    def _extract_features(self, raw_url):
        normalized = self._prepare_url(raw_url).lower()
        parsed = urlparse(normalized)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        full = normalized

        suspicious_terms = [
            "login",
            "verify",
            "secure",
            "update",
            "account",
            "password",
            "confirm",
            "billing",
            "bank",
            "bonus",
            "gift",
            "urgent",
            "wallet",
            "otp",
            "kyc",
            "reward",
            "suspended",
        ]
        brand_terms = [
            "paypal",
            "google",
            "microsoft",
            "apple",
            "amazon",
            "instagram",
            "facebook",
            "netflix",
            "dropbox",
            "linkedin",
            "icici",
            "hdfc",
            "sbi",
            "coinbase",
            "telegram",
            "nordvpn",
        ]
        risky_tlds = {".ru", ".tk", ".ml", ".gq", ".cf", ".xyz", ".top", ".click"}

        token_hits = sum(term in full for term in suspicious_terms)
        brand_hits = sum(term in full for term in brand_terms)
        digit_count = sum(ch.isdigit() for ch in full)
        letter_count = sum(ch.isalpha() for ch in full)
        special_count = sum(ch in "@-_=%" for ch in full)
        query_params = len(parse_qs(query))
        path_segments = len([part for part in path.split("/") if part])
        dots = hostname.count(".")
        subdomain_count = max(0, dots - 1)
        hyphens = hostname.count("-") + path.count("-")
        slash_count = full.count("/")
        equals_count = full.count("=")
        percent_count = full.count("%")
        uses_ip = False
        try:
            ipaddress.ip_address(hostname.strip("[]"))
            uses_ip = bool(hostname)
        except ValueError:
            uses_ip = False
        has_at = "@" in normalized
        punycode = "xn--" in hostname
        repeated_slashes = normalized.count("//") > 1
        https_scheme = parsed.scheme == "https"
        tld = ""
        if "." in hostname:
            tld = f".{hostname.split('.')[-1]}"

        return {
            "length": len(full),
            "hostname_length": len(hostname),
            "path_length": len(path),
            "query_length": len(query),
            "digit_count": digit_count,
            "letter_count": letter_count,
            "special_count": special_count,
            "dot_count": dots,
            "subdomain_count": subdomain_count,
            "hyphen_count": hyphens,
            "slash_count": slash_count,
            "equals_count": equals_count,
            "percent_count": percent_count,
            "path_segments": path_segments,
            "query_params": query_params,
            "suspicious_terms": token_hits,
            "brand_terms": brand_hits,
            "hostname_entropy": self._shannon_entropy(hostname),
            "full_entropy": self._shannon_entropy(full),
            "uses_https": int(https_scheme),
            "uses_ip": int(uses_ip),
            "has_at_symbol": int(has_at),
            "has_punycode": int(punycode),
            "risky_tld": int(tld in risky_tlds),
            "repeated_slashes": int(repeated_slashes),
            "tld": tld or "none",
        }

    def _rule_score(self, features, brand_analysis):
        score = 0
        score += 28 if features["uses_ip"] else 0
        score += 22 if features["has_at_symbol"] else 0
        score += 18 if features["risky_tld"] else 0
        score += min(features["suspicious_terms"] * 8, 32)
        score += 12 if features["brand_terms"] and features["hyphen_count"] >= 2 else 0
        score += 8 if features["length"] > 75 else 0
        score += 8 if features["subdomain_count"] >= 3 else 0
        score += 6 if features["query_params"] >= 3 else 0
        score += 5 if not features["uses_https"] else 0
        score += 18 if features["has_punycode"] else 0
        score += 8 if features["repeated_slashes"] else 0
        score += 6 if features["hostname_entropy"] >= 3.7 else 0
        score += 4 if features["digit_count"] >= 10 else 0
        score += 35 if brand_analysis["impersonated_brands"] else 0
        score -= 12 if brand_analysis["official_brands"] and not features["risky_tld"] else 0
        return max(0, min(score, 100))

    def _build_signals(self, features, brand_analysis=None):
        feature_signals = []
        brand_analysis = brand_analysis or {
            "official_brands": [],
            "impersonated_brands": [],
            "typo_brands": [],
        }
        if features["uses_ip"]:
            feature_signals.append("Uses an IP address instead of a readable domain")
        if features["has_at_symbol"]:
            feature_signals.append("Contains an @ symbol, which can hide the real destination")
        if features["risky_tld"]:
            feature_signals.append("Uses a top-level domain that is common in phishing kits")
        if features["suspicious_terms"] >= 2:
            feature_signals.append("Contains multiple urgency or credential-related keywords")
        if features["brand_terms"] and features["hyphen_count"] >= 2:
            feature_signals.append("Mixes brand names with extra hyphenated terms")
        if features["length"] > 75:
            feature_signals.append("The URL is unusually long")
        if features["subdomain_count"] >= 3:
            feature_signals.append("Uses many subdomains, which can disguise the real host")
        if features["query_params"] >= 3:
            feature_signals.append("Contains several query parameters")
        if features["has_punycode"]:
            feature_signals.append("Contains punycode, which can be used for lookalike domains")
        if not features["uses_https"]:
            feature_signals.append("Uses HTTP instead of HTTPS")
        if features["hostname_entropy"] >= 3.7:
            feature_signals.append("The host name looks unusually random")
        if brand_analysis["impersonated_brands"]:
            feature_signals.append(
                "Uses a trusted brand name on a domain that is not an official brand domain"
            )
        if brand_analysis["typo_brands"]:
            feature_signals.append("Looks like a misspelled version of a trusted brand domain")
        if brand_analysis["official_brands"]:
            feature_signals.append("Matches a known official brand domain")

        if not feature_signals:
            feature_signals.append("No strong phishing indicators were found in the URL structure")

        return feature_signals

    def _build_format_checks(self, validation, features=None):
        if not validation["valid"]:
            return validation["issues"]

        checks = ["URL format is valid"]
        checks.append("Uses HTTPS" if validation["scheme"] == "https" else "Uses HTTP")
        if validation["uses_ip"]:
            checks.append("Host is an IP address")
        else:
            checks.append(f"Domain detected: {validation['hostname']}")

        if features and features["path_segments"]:
            checks.append(f"Path segments found: {features['path_segments']}")
        if features and features["query_params"]:
            checks.append(f"Query parameters found: {features['query_params']}")
        return checks

    def _model_breakdown(self, features):
        vectorizer = self.pipeline.named_steps["vectorizer"]
        classifier = self.pipeline.named_steps["classifier"]
        transformed = vectorizer.transform([features])

        breakdown = {}
        for name, estimator in classifier.named_estimators_.items():
            probability = float(estimator.predict_proba(transformed)[0][1]) * 100
            breakdown[name] = round(probability, 2)
        return breakdown

    def _live_feedback(self, url, result):
        if not url.strip():
            return "idle", "Real-time scan is standing by."

        if not result["valid_url"]:
            issue = result["format_checks"][0] if result["format_checks"] else ""
            return "format", issue or "Finish the URL format to start the live scan."

        if result["is_phishing"]:
            return "alert", "Real-time scan found phishing-style patterns in this link."

        if result["risk_level"] == "Medium":
            return (
                "caution",
                "Real-time scan spotted a few warning signs. Double-check this link.",
            )

        return "clear", "Real-time scan has not found strong phishing signals so far."

    def _groq_review_unavailable(self, reason, enabled=False):
        return {
            "provider": "Groq",
            "enabled": enabled,
            "used": False,
            "available": False,
            "verdict": "Unavailable",
            "risk_level": "Unavailable",
            "confidence": None,
            "reason": reason,
            "model": None,
        }

    def _normalize_groq_payload(self, data, model_name):
        verdict = str(data.get("verdict", "Unclear")).strip() or "Unclear"
        risk_level = str(data.get("risk_level", "Medium")).strip().title() or "Medium"
        reason = str(data.get("reason", "Groq did not provide a reason.")).strip()

        confidence = data.get("confidence")
        try:
            if confidence is None:
                confidence = None
            else:
                confidence = max(0, min(100, int(round(float(confidence)))))
        except (TypeError, ValueError):
            confidence = None

        allowed_risk = {"Low", "Medium", "High"}
        if risk_level not in allowed_risk:
            risk_level = "Medium"

        return {
            "provider": "Groq",
            "enabled": True,
            "used": True,
            "available": True,
            "verdict": verdict,
            "risk_level": risk_level,
            "confidence": confidence,
            "reason": reason,
            "model": model_name,
        }

    def _groq_probability(self, groq_review):
        if not groq_review["available"]:
            return None

        confidence = groq_review["confidence"] if groq_review["confidence"] is not None else 50
        verdict = groq_review["verdict"].strip().lower()
        risk_level = groq_review["risk_level"]

        if verdict == "phishing":
            return float(confidence)
        if verdict == "legitimate":
            return float(100 - confidence)

        risk_bias = {"Low": 25.0, "Medium": 50.0, "High": 75.0}
        return risk_bias.get(risk_level, 50.0)

    def _extract_json_object(self, content):
        text = (content or "").strip()
        if not text:
            raise ValueError("Groq returned an empty response.")

        if text.startswith("```"):
            lines = text.splitlines()
            if len(lines) >= 3:
                text = "\n".join(lines[1:-1]).strip()

        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end < start:
            raise ValueError("Groq did not return JSON content.")

        return json.loads(text[start : end + 1])

    def _groq_review(self, normalized_url, signals):
        api_key = os.getenv("GROQ_API_KEY", "").strip()
        if not api_key:
            return self._groq_review_unavailable(
                "Set GROQ_API_KEY to enable a Groq phishing review."
            )

        model_name = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant").strip() or "llama-3.1-8b-instant"
        prompt_signals = "; ".join(signals[:4]) if signals else "No strong phishing indicators were found."
        payload = {
            "model": model_name,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a phishing URL analyst. "
                        "Inspect only the URL string and known phishing patterns. "
                        "Reply with valid JSON only using keys verdict, risk_level, confidence, reason. "
                        "verdict must be one of Phishing, Legitimate, or Unclear. "
                        "risk_level must be one of Low, Medium, or High. "
                        "confidence must be an integer from 0 to 100. "
                        "reason must be one short sentence."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"URL: {normalized_url}\n"
                        f"Local detector signals: {prompt_signals}\n"
                        "Return JSON only."
                    ),
                },
            ],
        }

        groq_request = request.Request(
            "https://api.groq.com/openai/v1/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with request.urlopen(groq_request, timeout=8) as response:
                raw_response = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="ignore").strip()
            reason = f"Groq API error {exc.code}."
            if detail:
                reason = f"{reason} {detail[:180]}"
            return self._groq_review_unavailable(reason, enabled=True)
        except error.URLError:
            return self._groq_review_unavailable(
                "Groq could not be reached from this server.", enabled=True
            )
        except (OSError, json.JSONDecodeError):
            return self._groq_review_unavailable(
                "Groq returned an unreadable response.", enabled=True
            )

        try:
            content = raw_response["choices"][0]["message"]["content"]
            parsed = self._extract_json_object(content)
        except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError):
            return self._groq_review_unavailable(
                "Groq returned a response that could not be parsed.", enabled=True
            )

        return self._normalize_groq_payload(parsed, model_name)

    def predict(self, url, analysis_mode="manual"):
        validation = self._validate_url(url)

        if not validation["valid"]:
            result = {
                "url": url,
                "normalized_url": validation["normalized_url"],
                "valid_url": False,
                "verdict": "Invalid URL format",
                "is_phishing": False,
                "risk_level": "Invalid",
                "phishing_probability": 0.0,
                "legitimate_probability": 0.0,
                "signals": ["Phishing analysis runs only after the URL format is valid"],
                "format_checks": self._build_format_checks(validation),
                "features": {},
                "ai_models": {},
                "ai_summary": "No AI analysis was run because the URL format is invalid.",
                "analysis_mode": analysis_mode,
                "groq_review": self._groq_review_unavailable(
                    "Groq review starts after the URL format is valid.",
                    enabled=bool(os.getenv("GROQ_API_KEY", "").strip()),
                ),
                "groq_summary": "",
            }
            live_status, live_message = self._live_feedback(url, result)
            result["live_status"] = live_status
            result["live_message"] = live_message
            return result

        features = self._extract_features(validation["normalized_url"])
        brand_analysis = self._brand_domain_analysis(validation["hostname"])
        model_breakdown = self._model_breakdown(features)
        ensemble_probability = float(self.pipeline.predict_proba([features])[0][1]) * 100
        rule_probability = self._rule_score(features, brand_analysis)
        phishing_probability = round(
            min(100.0, (ensemble_probability * 0.7) + (rule_probability * 0.3)), 2
        )

        if features["uses_ip"] and features["suspicious_terms"] >= 2:
            phishing_probability = max(phishing_probability, 88.0)
        if features["has_at_symbol"] and features["risky_tld"]:
            phishing_probability = max(phishing_probability, 92.0)
        if brand_analysis["impersonated_brands"]:
            phishing_probability = max(phishing_probability, 90.0)

        groq_review = (
            self._groq_review(
                validation["normalized_url"], self._build_signals(features, brand_analysis)
            )
            if analysis_mode == "manual"
            else self._groq_review_unavailable(
                "Groq review is skipped during the real-time scan to avoid extra latency.",
                enabled=bool(os.getenv("GROQ_API_KEY", "").strip()),
            )
        )
        groq_probability = self._groq_probability(groq_review)
        if groq_probability is not None:
            phishing_probability = round((phishing_probability * 0.65) + (groq_probability * 0.35), 2)

        if brand_analysis["official_brands"] and not brand_analysis["impersonated_brands"]:
            if not features["risky_tld"] and not features["has_at_symbol"] and not features["uses_ip"]:
                phishing_probability = min(phishing_probability, 18.0)

        is_phishing = phishing_probability >= 50
        risk_level = (
            "High"
            if phishing_probability >= 70
            else "Medium"
            if phishing_probability >= 45
            else "Low"
        )

        if brand_analysis["impersonated_brands"]:
            ai_summary = (
                "This URL uses a trusted brand name on a domain that does not match the official site."
            )
        elif brand_analysis["official_brands"]:
            ai_summary = "This URL matches a known official brand domain."
        else:
            ai_summary = (
                "AI ensemble models agree that this URL looks suspicious."
                if is_phishing
                else "AI ensemble models lean toward this URL being legitimate."
            )

        result = {
            "url": url,
            "normalized_url": validation["normalized_url"],
            "valid_url": True,
            "verdict": "Phishing" if is_phishing else "Not phishing",
            "is_phishing": is_phishing,
            "risk_level": risk_level,
            "phishing_probability": round(phishing_probability, 2),
            "legitimate_probability": round(100 - phishing_probability, 2),
            "signals": self._build_signals(features, brand_analysis),
            "format_checks": self._build_format_checks(validation, features),
            "features": {
                "Normalized URL": validation["normalized_url"],
                "Registered domain": brand_analysis["registered_domain"],
                "Dot count": features["dot_count"],
                "Subdomains": features["subdomain_count"],
                "Hyphen count": features["hyphen_count"],
                "Suspicious keywords": features["suspicious_terms"],
                "Brand keywords": features["brand_terms"],
                "Hostname entropy": features["hostname_entropy"],
                "Query parameters": features["query_params"],
                "Uses HTTPS": "Yes" if features["uses_https"] else "No",
                "Uses IP address": "Yes" if features["uses_ip"] else "No",
                "Risky TLD": "Yes" if features["risky_tld"] else "No",
                "Official brand match": ", ".join(brand_analysis["official_brands"]) or "No",
                "Brand impersonation": ", ".join(brand_analysis["impersonated_brands"]) or "No",
                "Brand typo detected": ", ".join(brand_analysis["typo_brands"]) or "No",
            },
            "ai_models": {
                "Logistic Regression": model_breakdown["logistic"],
                "Random Forest": model_breakdown["forest"],
                "Gradient Boosting": model_breakdown["boosting"],
                "Rule Engine": round(rule_probability, 2),
            },
            "ai_summary": ai_summary,
            "analysis_mode": analysis_mode,
            "groq_review": groq_review,
            "groq_summary": (
                f"Groq review: {groq_review['verdict']} ({groq_review['risk_level']}). {groq_review['reason']}"
                if groq_review["available"]
                else groq_review["reason"]
                if analysis_mode == "manual"
                else ""
            ),
        }
        if groq_review["available"]:
            result["ai_models"]["Groq confidence"] = groq_review["confidence"]
            result["ai_models"]["Groq verdict"] = (
                f"{groq_review['verdict']} ({groq_review['risk_level']})"
            )
        live_status, live_message = self._live_feedback(url, result)
        result["live_status"] = live_status
        result["live_message"] = live_message
        return result

    def predict_realtime(self, url):
        if not url.strip():
            return {
                "url": url,
                "normalized_url": "",
                "valid_url": False,
                "verdict": "Waiting for input",
                "is_phishing": False,
                "risk_level": "Idle",
                "phishing_probability": 0.0,
                "legitimate_probability": 0.0,
                "signals": ["Real-time phishing checks begin after you enter a URL."],
                "format_checks": ["Type a URL such as example.com or https://example.com."],
                "features": {},
                "ai_models": {},
                "ai_summary": "Live scan is standing by.",
                "analysis_mode": "realtime",
                "groq_review": self._groq_review_unavailable(
                    "Groq review is available only for the full manual analysis.",
                    enabled=bool(os.getenv("GROQ_API_KEY", "").strip()),
                ),
                "groq_summary": "",
                "live_status": "idle",
                "live_message": "Real-time scan is standing by.",
            }

        return self.predict(url, analysis_mode="realtime")
