from statistics import plot_register_log_latency

from application import AuthServer

import tempfile

_protections_1 = {
    # "pepper": "137379782",
    # "rate_limit": {"tokens": 4, "refill_rate_tps": 0},
    # "lockout": {"tokens": 3, "token_rate": 2, "duration_rate": 1, "duration_mm": 0.1},
    "captcha": {"tokens": 3, "time_to_live": 60},
    # "totp": {"number_of_users": 5, "length": 5, "period_ss": 30}
}


def main():
    # plot_register_log_latency()
    temp = tempfile.TemporaryDirectory()
    server = AuthServer(directory_path=temp.name, enabled_protections=_protections_1)
    print("Creating server...")
    server.run(debug=True)


if __name__ == "__main__":
    main()
