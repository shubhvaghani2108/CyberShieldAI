import dns.resolver


def get_dns_records(domain):

    result = {

        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "CNAME": []

    }


    record_types = [
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT",
        "CNAME"
    ]


    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 3.0

    for record in record_types:
        try:
            answers = resolver.resolve(domain, record)
            for answer in answers:
                result[record].append(str(answer))
        except Exception:
            result[record] = []

    # If MX, NS, or TXT are empty on a subdomain (e.g. www.google.com -> google.com), fallback to apex domain
    parts = domain.split(".")
    if len(parts) > 2 and (not result["MX"] or not result["NS"] or not result["TXT"]):
        apex_domain = ".".join(parts[-2:])
        for apex_record in ["MX", "NS", "TXT"]:
            if not result[apex_record]:
                try:
                    apex_answers = resolver.resolve(apex_domain, apex_record)
                    for ans in apex_answers:
                        result[apex_record].append(str(ans))
                except Exception:
                    pass

    return result

if __name__ == "__main__":

    from pprint import pprint

    pprint(
        get_dns_records("google.com")
    )