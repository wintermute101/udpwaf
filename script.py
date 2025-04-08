def filter(*args):
    print(f"Python: Bytes: {args[0]} addr {args[1]}")

    #with open("output.txt", "ab") as f: # works with -w allow write in current dir
    #    f.write(args[0])
    #    f.write(b"\n")

    if args[0].find(b"bad_string") > -1:
        return None
    else:
        return args[0]