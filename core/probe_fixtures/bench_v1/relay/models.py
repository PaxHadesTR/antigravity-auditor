class User:
    def __init__(self, user_id, email, role="member", balance=0):
        self.user_id = user_id
        self.email = email
        self.role = role
        self.balance = balance
