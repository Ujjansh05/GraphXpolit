"""Sample demo application entry point."""

from auth import authenticate, get_user_role
from calculator import calculate_total, apply_discount
from database import get_connection, fetch_orders


def main():
    """Main application workflow."""

    user = authenticate("admin")
    role = get_user_role(user)

    conn = get_connection()
    orders = fetch_orders(conn, user_id=user["id"])

    for order in orders:
        total = calculate_total(order["items"])
        if role == "premium":
            total = apply_discount(total, percent=15)
        print(f"Order #{order['id']}: ${total:.2f}")


if __name__ == "__main__":
