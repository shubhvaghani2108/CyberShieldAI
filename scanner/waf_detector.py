import requests


WAF_SIGNATURES = {

    "Cloudflare": [

        "cloudflare",

        "cf-ray",

        "cf-cache-status"

    ],

    "Akamai": [

        "akamai",

        "akamaighost"

    ],

    "Sucuri": [

        "sucuri"

    ],

    "Imperva": [

        "incapsula",

        "imperva"

    ],

    "AWS WAF": [

        "awselb",

        "x-amzn"

    ],

    "Azure Front Door": [

        "azure",

        "frontdoor"

    ],

    "Fastly": [

        "fastly"

    ]

}


def detect_waf(url):

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

        response = requests.get(
            url,
            headers=headers,
            timeout=8,
            allow_redirects=True,
            verify=False
        )

        headers = response.headers

        combined = ""

        for k, v in headers.items():

            combined += f"{k}:{v}\n"

        combined = combined.lower()

        for waf, signatures in WAF_SIGNATURES.items():

            for sig in signatures:

                if sig.lower() in combined:

                    return {

                        "detected": True,

                        "provider": waf,

                        "confidence": "High"

                    }

        return {

            "detected": False,

            "provider": "None",

            "confidence": "Low"

        }

    except Exception as e:

        return {

            "detected": False,

            "provider": "Unknown",

            "confidence": "Unknown",

            "error": str(e)

        }


if __name__ == "__main__":

    from pprint import pprint

    pprint(

        detect_waf("https://google.com")

    )