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

        response = requests.get(

            url,

            timeout=5,

            allow_redirects=True

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