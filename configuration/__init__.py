# config/__init__.py

from .config import config
from .users import dummy_members, USERS_FILE_PATH

GROUP_SEED = config.group_seed

hash_mode = config.hash_mode
get_hash_params = config.get_hash_params

protections = config.protections
get_protection_with_params = config.get_protection_with_params

get_password_params = config.get_password_params

get_random_user = dummy_members.get_random_user
add_user = dummy_members.add_user
