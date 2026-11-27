def get_users():
    """Return every user."""
    return []


def post_create_user(name: str, age: int = 18):
    """Create a user."""
    return {"name": name, "age": age}


def put_update_item(item_id: int, title: str):
    """Update an item."""
    return {"id": item_id, "title": title}


def delete_user(uid: int):
    """Delete a user."""
    return True
