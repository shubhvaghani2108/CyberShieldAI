from database.ssl_results import save_ssl as _save_ssl


def save_ssl(data, scan_id=None):
    """
    Saves SSL scan results into ssl_results.
    """
    _save_ssl(data, scan_id=scan_id)