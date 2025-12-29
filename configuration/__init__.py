# configuration/__init__.py

from .config import config
from .users import DummyMembersManager

# Global identifier used for experiments and administrative actions
GROUP_SEED = config.group_seed

# Password hashing configuration
hash_mode = config.hash_mode
get_hash_params = config.get_hash_params
get_environmental_pepper = config.get_environmental_pepper

# Security protections configuration
protections = config.get_protection_with_params()
rate_limit_parameters = config.rate_limit_parameters
lockout_parameters = config.lockout_parameters
captcha_parameters = config.captcha_parameters
totp_parameters = config.totp_parameters

# Password generation configuration (used by attacks and dummy users)
get_password_params = config.get_password_params
generate_password = DummyMembersManager.generate_password
