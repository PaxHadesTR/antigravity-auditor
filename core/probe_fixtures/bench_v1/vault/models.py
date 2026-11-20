import config


class User:
    def __init__(self, user_id, name, is_admin=False):
        self.user_id = user_id
        self.name = name
        self.is_admin = is_admin


def greeting(user, template):
    # Users pick their own greeting, e.g. "Good morning, {user.name}!"
    return template.format(user=user)


def cache_dir():
    return config.DOCS_ROOT + "/.cache"
