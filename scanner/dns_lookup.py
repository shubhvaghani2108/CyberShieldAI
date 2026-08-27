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
            answers = resolver.resolve(
                domain,
                record
            )

            for answer in answers:
                result[record].append(
                    str(answer)
                )

        except Exception:
            result[record] = []

    return result

if __name__ == "__main__":

    from pprint import pprint

    pprint(
        get_dns_records("google.com")
    )