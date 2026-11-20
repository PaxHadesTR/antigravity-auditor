import random
import secrets
import time


def transfer(db, src_id, dst_id, amount):
    balance = db.balance(src_id)
    if amount > balance:
        raise ValueError("insufficient funds")
    db.set_balance(src_id, balance - amount)
    db.set_balance(dst_id, db.balance(dst_id) + amount)


def refund(db, payment_id, merchant_id):
    payment = db.payment(payment_id)
    if payment is None or payment["merchant_id"] != merchant_id or payment["refunded"]:
        raise PermissionError("not your payment")
    transfer(db, merchant_id, payment["payer_id"], payment["amount"])
    db.mark_refunded(payment_id)


def apply_fee(formula, amount):
    # Merchants write their own fee formula, e.g. "amount * 0.02 + 30".
    return eval(formula, {"__builtins__": {}}, {"amount": amount})


def reset_token():
    rng = random.Random(int(time.time()))
    return "%016x" % rng.getrandbits(64)


def invite_code():
    return secrets.token_urlsafe(16)
