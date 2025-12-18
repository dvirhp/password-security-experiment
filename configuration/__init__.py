# configuration/__init__.py

from .config import config
from .users import DummyMembersManager

GROUP_SEED = config.group_seed

hash_mode = config.hash_mode
get_hash_params = config.get_hash_params

protections = config.protections
get_protection_with_params = config.get_protection_with_params
rate_limit_parameters = config.rate_limit_parameters
lockout_parameters = config.lockout_parameters

get_password_params = config.get_password_params

generate_password = DummyMembersManager.generate_password
