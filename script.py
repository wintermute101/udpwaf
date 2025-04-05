def filter(*args):
    print(f"Python: Bytes: {args[0]} addr {args[1]}")

    if args[0].find(b"bad_string") > -1:
        return None
    else:
        return args[0]