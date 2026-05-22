import json, os

_STATE_FILE  = os.path.join(os.path.dirname(__file__), "vault", "lockout.json")
MAX_ATTEMPTS = 5

def _load():
    if os.path.exists(_STATE_FILE):
        try:
            with open(_STATE_FILE) as f: return json.load(f)
        except: pass
    return {}

def _save(state):
    os.makedirs(os.path.dirname(_STATE_FILE), exist_ok=True)
    with open(_STATE_FILE, "w") as f: json.dump(state, f, indent=2)

def is_locked(filename):
    return _load().get(filename, {}).get("locked", False)

def get_attempts(filename):
    return _load().get(filename, {}).get("attempts", 0)

def record_failure(filename):
    state = _load()
    entry = state.get(filename, {"attempts": 0, "locked": False})
    entry["attempts"] += 1
    if entry["attempts"] >= MAX_ATTEMPTS:
        entry["locked"] = True
    state[filename] = entry
    _save(state)

def record_success(filename):
    state = _load()
    state.pop(filename, None)
    _save(state)

def unlock(filename):
    state = _load()
    state.pop(filename, None)
    _save(state)

def unlock_all():
    _save({})
